"""Per-packet and batch-level DNS anomaly detection.

build_dns_record() turns one scapy packet into a structured record (Pass
1). apply_detection_signals() then looks at the *whole* batch of records
to compute per-host entropy baselines, subdomain-burst groups, and
per-client NXDOMAIN ratios - signals a single packet can't produce on
its own (Pass 2). See DOCUMENTATION.md section 1.3c for the full design
writeup.
"""

import logging
import math
import statistics
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, List, NamedTuple, Optional, Set, Tuple

from scapy.all import DNS, DNSQR, IP, Packet

from dns_analyzer.dns_parsing import calculate_entropy, parse_dns_flags, parse_domain

logger = logging.getLogger(__name__)

DEFAULT_ENTROPY_THRESHOLD = 3.5
DEFAULT_Z_SCORE_THRESHOLD = 3.0
DEFAULT_MIN_BASELINE_SAMPLES = 5
DEFAULT_BURST_WINDOW_SECONDS = 60
DEFAULT_BURST_UNIQUE_SUBDOMAIN_THRESHOLD = 15
DEFAULT_NXDOMAIN_RATIO_THRESHOLD = 0.5
DEFAULT_MIN_NXDOMAIN_SAMPLES = 5


@dataclass
class DetectionSettings:
    """Tunable thresholds for the detection heuristics below."""

    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD
    z_score_threshold: float = DEFAULT_Z_SCORE_THRESHOLD
    min_baseline_samples: int = DEFAULT_MIN_BASELINE_SAMPLES
    burst_window_seconds: int = DEFAULT_BURST_WINDOW_SECONDS
    burst_unique_subdomain_threshold: int = DEFAULT_BURST_UNIQUE_SUBDOMAIN_THRESHOLD
    nxdomain_ratio_threshold: float = DEFAULT_NXDOMAIN_RATIO_THRESHOLD
    min_nxdomain_samples: int = DEFAULT_MIN_NXDOMAIN_SAMPLES


class HostEntropyBaseline(NamedTuple):
    mean: float
    stdev: float
    sample_count: int


class NxdomainStats(NamedTuple):
    ratio: float
    sample_count: int


def generate_remark(
    entropy: float,
    flags: Dict[str, str],
    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    z_score: Optional[float] = None,
    z_score_threshold: float = DEFAULT_Z_SCORE_THRESHOLD,
) -> str:
    """Generate a remark based on entropy, DNS flags, and (optionally) a
    per-host entropy z-score computed by apply_detection_signals().
    """
    if entropy > entropy_threshold:
        return "High entropy domain name - Possible DGA or DNS Tunneling"
    if z_score is not None and z_score > z_score_threshold:
        return f"Entropy anomalous for this host (z={z_score:.2f}) - Possible DGA or DNS Tunneling"
    if flags["rcode"] == "REFUSED":
        return "DNS query refused by the server"
    if flags["qr"] == "RESPONSE" and flags["rcode"] != "NOERROR":
        return "Unsuccessful DNS response - Possible misconfiguration or attack"
    return "Normal query"


def build_dns_record(packet: Packet, entropy_threshold: float) -> Optional[Dict[str, Any]]:
    """Build a structured analysis record from a captured DNS packet.

    Returns None if the packet has no IP layer (e.g. non-IPv4 traffic),
    since source/destination cannot be determined in that case.

    The remark here only reflects the fixed entropy threshold and DNS
    flags - per-host statistical baselining, subdomain-burst detection,
    and NXDOMAIN-ratio tracking all need the *full* batch of records to
    compute, so apply_detection_signals() refines "remark" (and adds new
    fields) afterward once every packet in the capture has been parsed.
    """
    if not packet.haslayer(IP):
        return None

    dns = packet[DNS]
    dns_query = (
        packet[DNSQR].qname.decode("utf-8") if packet.haslayer(DNSQR) else "Unknown"
    )
    domain_parts = parse_domain(dns_query)
    entropy = calculate_entropy(domain_parts.scoring_label)
    flags = parse_dns_flags(dns)
    remark = generate_remark(entropy, flags, entropy_threshold)

    return {
        "source_ip": packet[IP].src,
        "destination_ip": packet[IP].dst,
        "query": dns_query,
        "registrable_domain": domain_parts.registrable_domain,
        "subdomain": domain_parts.subdomain,
        "entropy": entropy,
        "entropy_z_score": None,
        "timestamp": float(packet.time),
        "qdcount": dns.qdcount,
        "ancount": dns.ancount,
        "nscount": dns.nscount,
        "arcount": dns.arcount,
        "flags": flags,
        "subdomain_burst": False,
        "subdomain_burst_unique_count": None,
        "host_nxdomain_ratio": None,
        "threat_intel": None,
        "severity": None,
        "remark": remark,
    }


def compute_host_baselines(
    records: List[Dict[str, Any]],
    min_samples: int = DEFAULT_MIN_BASELINE_SAMPLES,
) -> Dict[str, HostEntropyBaseline]:
    """Compute a per-source-host entropy baseline (mean, population stdev)
    from QUERY records in a batch. Hosts with fewer than min_samples
    queries are excluded - too little data for a stable baseline.
    """
    entropies_by_host: Dict[str, List[float]] = defaultdict(list)
    for record in records:
        if record["flags"]["qr"] != "QUERY":
            continue
        entropies_by_host[record["source_ip"]].append(record["entropy"])

    baselines: Dict[str, HostEntropyBaseline] = {}
    for host, entropies in entropies_by_host.items():
        if len(entropies) >= min_samples:
            baselines[host] = HostEntropyBaseline(
                mean=statistics.mean(entropies),
                stdev=statistics.pstdev(entropies),
                sample_count=len(entropies),
            )
    return baselines


def entropy_z_score(entropy: float, baseline: Optional[HostEntropyBaseline]) -> Optional[float]:
    """Return how many standard deviations `entropy` is from a host's
    baseline, or None if there's no baseline or it has zero variance
    (a constant baseline can't meaningfully flag a deviation via z-score).
    """
    if baseline is None or baseline.stdev == 0:
        return None
    return (entropy - baseline.mean) / baseline.stdev


def detect_subdomain_bursts(
    records: List[Dict[str, Any]],
    window_seconds: int = DEFAULT_BURST_WINDOW_SECONDS,
    unique_threshold: int = DEFAULT_BURST_UNIQUE_SUBDOMAIN_THRESHOLD,
) -> Dict[Tuple[str, int], Set[str]]:
    """Group QUERY records by (registrable_domain, time-window bucket) and
    collect the set of unique subdomain labels queried in each bucket.
    Returns only buckets meeting unique_threshold - many unique
    subdomains under one parent domain in a short window is a classic
    DNS-tunneling signal, independent of any single query's entropy.
    """
    buckets: Dict[Tuple[str, int], Set[str]] = defaultdict(set)
    for record in records:
        if record["flags"]["qr"] != "QUERY":
            continue
        if not record["registrable_domain"] or not record["subdomain"]:
            continue
        bucket = int(record["timestamp"] // window_seconds)
        buckets[(record["registrable_domain"], bucket)].add(record["subdomain"])

    return {key: subs for key, subs in buckets.items() if len(subs) >= unique_threshold}


def compute_nxdomain_ratios(
    records: List[Dict[str, Any]],
    min_samples: int = DEFAULT_MIN_NXDOMAIN_SAMPLES,
) -> Dict[str, NxdomainStats]:
    """Compute, per querying client, the fraction of DNS responses that
    came back NXDOMAIN. A client with a high NXDOMAIN ratio is a classic
    indicator of a DGA-infected host cycling through candidate C2
    domains until one resolves.

    Keyed by destination_ip because on a RESPONSE packet the client is
    the destination, not the source (the source is the answering DNS
    server) - getting this backwards would baseline the wrong host.
    """
    counts: Dict[str, List[int]] = defaultdict(lambda: [0, 0])  # [nxdomain, total]
    for record in records:
        if record["flags"]["qr"] != "RESPONSE":
            continue
        client = record["destination_ip"]
        counts[client][1] += 1
        if record["flags"]["rcode"] == "NXDOMAIN":
            counts[client][0] += 1

    return {
        host: NxdomainStats(ratio=nx / total, sample_count=total)
        for host, (nx, total) in counts.items()
        if total >= min_samples
    }


def apply_detection_signals(
    records: List[Dict[str, Any]],
    settings: DetectionSettings,
) -> List[Dict[str, Any]]:
    """Refine records in place with batch-level detection signals that a
    single packet can't produce on its own: per-host entropy baselining
    (z-score), subdomain-burst detection, and per-client NXDOMAIN ratio.
    Also finalizes each record's "remark" to reflect all signals.
    """
    baselines = compute_host_baselines(records, settings.min_baseline_samples)
    bursts = detect_subdomain_bursts(
        records, settings.burst_window_seconds, settings.burst_unique_subdomain_threshold
    )
    nxdomain_ratios = compute_nxdomain_ratios(records, settings.min_nxdomain_samples)

    for record in records:
        is_query = record["flags"]["qr"] == "QUERY"

        baseline = baselines.get(record["source_ip"]) if is_query else None
        z_score = entropy_z_score(record["entropy"], baseline)
        record["entropy_z_score"] = z_score

        remark = generate_remark(
            record["entropy"], record["flags"], settings.entropy_threshold,
            z_score=z_score, z_score_threshold=settings.z_score_threshold,
        )
        notes: List[str] = []

        if is_query and record["registrable_domain"] and record["subdomain"]:
            bucket = int(record["timestamp"] // settings.burst_window_seconds)
            burst_key = (record["registrable_domain"], bucket)
            if burst_key in bursts:
                unique_count = len(bursts[burst_key])
                record["subdomain_burst"] = True
                record["subdomain_burst_unique_count"] = unique_count
                notes.append(
                    f"{unique_count} unique subdomains under {record['registrable_domain']} "
                    f"within {settings.burst_window_seconds}s - possible DNS tunneling"
                )

        if not is_query:
            nx_stats = nxdomain_ratios.get(record["destination_ip"])
            if nx_stats is not None:
                record["host_nxdomain_ratio"] = nx_stats.ratio
                if nx_stats.ratio >= settings.nxdomain_ratio_threshold:
                    notes.append(
                        f"host {record['destination_ip']} has a high NXDOMAIN ratio "
                        f"({nx_stats.ratio:.0%} of {nx_stats.sample_count} responses) - "
                        f"possible DGA client"
                    )

        if notes:
            remark = remark + " | " + " | ".join(notes)
        record["remark"] = remark

    return records


# --- Streaming/incremental equivalents (Phase 4 - live capture) ------------
#
# apply_detection_signals() above needs the *entire* batch in memory to
# compute baselines/bursts/ratios, which only works once a capture is
# complete. For live capture there is no "complete batch" - detection has
# to happen as each packet arrives, using O(1)-ish incremental algorithms
# instead of re-scanning everything seen so far. These deliberately reuse
# HostEntropyBaseline/entropy_z_score/NxdomainStats/generate_remark from
# above so live and batch mode share the same scoring logic - only *how*
# the baseline/window/ratio is computed differs.


class WelfordAccumulator:
    """Streaming mean/variance via Welford's online algorithm - O(1) time
    and memory per update, unlike compute_host_baselines() which needs
    every record kept in memory to recompute statistics.mean/pstdev.
    """

    def __init__(self) -> None:
        self.count = 0
        self._mean = 0.0
        self._m2 = 0.0

    def update(self, value: float) -> None:
        self.count += 1
        delta = value - self._mean
        self._mean += delta / self.count
        delta2 = value - self._mean
        self._m2 += delta * delta2

    @property
    def stdev(self) -> float:
        if self.count < 2:
            return 0.0
        return math.sqrt(self._m2 / self.count)  # population stdev, matching statistics.pstdev

    def baseline(self, min_samples: int) -> Optional[HostEntropyBaseline]:
        if self.count < min_samples:
            return None
        return HostEntropyBaseline(mean=self._mean, stdev=self.stdev, sample_count=self.count)


class SubdomainBurstTracker:
    """Rolling-window unique-subdomain-count tracker per registrable
    domain. Unlike detect_subdomain_bursts()'s fixed time buckets (which
    can split one burst across two buckets at a boundary - a documented
    batch-mode limitation), this is a genuine sliding window: each
    observation evicts entries older than window_seconds before counting.
    """

    def __init__(self, window_seconds: float) -> None:
        self.window_seconds = window_seconds
        self._windows: Dict[str, Deque[Tuple[float, str]]] = defaultdict(deque)

    def observe(self, registrable_domain: str, subdomain: str, timestamp: float) -> int:
        """Record an observation and return the current unique-subdomain
        count within the trailing window for that registrable domain."""
        window = self._windows[registrable_domain]
        window.append((timestamp, subdomain))
        cutoff = timestamp - self.window_seconds
        while window and window[0][0] < cutoff:
            window.popleft()
        return len({sub for _, sub in window})


class NxdomainRatioTracker:
    """Running (cumulative, for the life of the tracker) NXDOMAIN ratio
    per client - the streaming equivalent of compute_nxdomain_ratios().
    """

    def __init__(self) -> None:
        self._counts: Dict[str, List[int]] = defaultdict(lambda: [0, 0])  # [nxdomain, total]

    def observe(self, client_ip: str, is_nxdomain: bool) -> NxdomainStats:
        counts = self._counts[client_ip]
        counts[1] += 1
        if is_nxdomain:
            counts[0] += 1
        return NxdomainStats(ratio=counts[0] / counts[1], sample_count=counts[1])


class LiveDetectionEngine:
    """Incremental, per-record equivalent of apply_detection_signals().

    Call process(record) once per parsed record, in arrival order; each
    call mutates and returns the record with entropy_z_score/subdomain_
    burst/host_nxdomain_ratio/remark filled in, using only the state
    accumulated so far - never a full-batch rescan.

    One deliberate difference from batch mode: a record's own entropy is
    scored against the host's baseline *before* that record is folded
    into the baseline (update() happens after scoring). Batch mode scores
    every record against a baseline computed from the *entire* batch,
    including itself, which numerically dampens outliers pulling their
    own mean/stdev up. Scoring against prior history only is both the
    more standard approach for online anomaly detection and the only
    causally sensible one for a live stream - but it means live and batch
    can produce a different z-score for the same data. See
    DOCUMENTATION.md for the full writeup.
    """

    def __init__(self, settings: DetectionSettings) -> None:
        self.settings = settings
        self._host_baselines: Dict[str, WelfordAccumulator] = defaultdict(WelfordAccumulator)
        self._burst_tracker = SubdomainBurstTracker(settings.burst_window_seconds)
        self._nxdomain_tracker = NxdomainRatioTracker()

    def process(self, record: Dict[str, Any]) -> Dict[str, Any]:
        is_query = record["flags"]["qr"] == "QUERY"
        z_score = None

        if is_query:
            accumulator = self._host_baselines[record["source_ip"]]
            baseline = accumulator.baseline(self.settings.min_baseline_samples)
            z_score = entropy_z_score(record["entropy"], baseline)
            accumulator.update(record["entropy"])

        record["entropy_z_score"] = z_score
        remark = generate_remark(
            record["entropy"], record["flags"], self.settings.entropy_threshold,
            z_score=z_score, z_score_threshold=self.settings.z_score_threshold,
        )
        notes: List[str] = []

        if is_query and record["registrable_domain"] and record["subdomain"]:
            unique_count = self._burst_tracker.observe(
                record["registrable_domain"], record["subdomain"], record["timestamp"]
            )
            if unique_count >= self.settings.burst_unique_subdomain_threshold:
                record["subdomain_burst"] = True
                record["subdomain_burst_unique_count"] = unique_count
                notes.append(
                    f"{unique_count} unique subdomains under {record['registrable_domain']} "
                    f"within {self.settings.burst_window_seconds}s - possible DNS tunneling"
                )

        if not is_query:
            is_nxdomain = record["flags"]["rcode"] == "NXDOMAIN"
            nx_stats = self._nxdomain_tracker.observe(record["destination_ip"], is_nxdomain)
            if nx_stats.sample_count >= self.settings.min_nxdomain_samples:
                record["host_nxdomain_ratio"] = nx_stats.ratio
                if nx_stats.ratio >= self.settings.nxdomain_ratio_threshold:
                    notes.append(
                        f"host {record['destination_ip']} has a high NXDOMAIN ratio "
                        f"({nx_stats.ratio:.0%} of {nx_stats.sample_count} responses) - "
                        f"possible DGA client"
                    )

        if notes:
            remark = remark + " | " + " | ".join(notes)
        record["remark"] = remark
        return record
