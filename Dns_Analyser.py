import argparse
import json
import logging
import statistics
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional, Set, Tuple

import numpy as np
import tldextract
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from scapy.all import DNS, DNSQR, IP, UDP, Packet, rdpcap, sniff, wrpcap

logger = logging.getLogger("dns_analyzer")

DEFAULT_ENTROPY_THRESHOLD = 3.5
DEFAULT_Z_SCORE_THRESHOLD = 3.0
DEFAULT_MIN_BASELINE_SAMPLES = 5
DEFAULT_BURST_WINDOW_SECONDS = 60
DEFAULT_BURST_UNIQUE_SUBDOMAIN_THRESHOLD = 15
DEFAULT_NXDOMAIN_RATIO_THRESHOLD = 0.5
DEFAULT_MIN_NXDOMAIN_SAMPLES = 5

MARGIN_LEFT = 50
MARGIN_TOP = 750
LINE_SPACING = 20

# Public-suffix-aware domain parser. suffix_list_urls=() disables fetching
# an updated Public Suffix List over the network and uses the bundled
# snapshot only, so this stays deterministic and works fully offline
# (important for a security tool that may run in isolated environments).
_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

# DNS Opcode / RCODE value -> name lookups (RFC 1035, RFC 6895).
# Using dicts with a fallback instead of list indexing avoids IndexError
# on the less common values (e.g. NOTIFY/UPDATE opcodes, extended RCODEs)
# that a fixed-size list would silently not cover.
OPCODES = {
    0: "QUERY", 1: "IQUERY", 2: "STATUS", 3: "RESERVED",
    4: "NOTIFY", 5: "UPDATE", 6: "DSO",
}
RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET",
    8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE",
}


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


class DomainParts(NamedTuple):
    registrable_domain: str  # "" if the public suffix couldn't be determined
    subdomain: str  # "" if the query has no subdomain labels
    scoring_label: str  # everything except the public suffix (TLD)


class HostEntropyBaseline(NamedTuple):
    mean: float
    stdev: float
    sample_count: int


class NxdomainStats(NamedTuple):
    ratio: float
    sample_count: int


def calculate_entropy(domain: str) -> float:
    """Calculate Shannon entropy of a domain name (or domain label)."""
    if not domain:
        return 0.0
    prob = [float(domain.count(c)) / len(domain) for c in set(domain)]
    return -sum(p * np.log2(p) for p in prob)


def parse_domain(domain: str) -> DomainParts:
    """Split a domain into its public-suffix-aware parts.

    The public suffix (TLD, e.g. 'com' or 'co.uk') is fixed and
    low-entropy by construction, so including it when scoring entropy
    dilutes the signal. scoring_label is everything the *registrant*
    controls (subdomain + registrable-domain label), which is where DGA
    randomness or DNS-tunneling-encoded data actually shows up.
    """
    clean = domain.rstrip(".")
    ext = _TLD_EXTRACTOR(clean)
    if not ext.domain or not ext.suffix:
        return DomainParts(registrable_domain="", subdomain="", scoring_label=clean)
    registrable_domain = f"{ext.domain}.{ext.suffix}"
    scoring_parts = [part for part in (ext.subdomain, ext.domain) if part]
    return DomainParts(
        registrable_domain=registrable_domain,
        subdomain=ext.subdomain,
        scoring_label=".".join(scoring_parts),
    )


def parse_dns_flags(dns: DNS) -> Dict[str, str]:
    """Map DNS flag values to human-readable format."""
    return {
        "qr": "RESPONSE" if dns.qr else "QUERY",
        "opcode": OPCODES.get(dns.opcode, f"UNKNOWN({dns.opcode})"),
        "aa": "TRUE" if dns.aa else "FALSE",
        "tc": "TRUE" if dns.tc else "FALSE",
        "rd": "TRUE" if dns.rd else "FALSE",
        "ra": "TRUE" if dns.ra else "FALSE",
        "rcode": RCODES.get(dns.rcode, f"UNKNOWN({dns.rcode})"),
    }


def format_flags(flags: Dict[str, str]) -> str:
    """Format the flags dictionary for better readability in the PDF."""
    return "\n".join([f"  {key}: {value}" for key, value in flags.items()])


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


def capture_dns_packets(duration: int, iface: Optional[str], pcap_file: str) -> List[Packet]:
    """Capture DNS packets for a user-defined duration and save them to a pcap file."""
    captured_packets: List[Packet] = []

    def packet_handler(packet: Packet) -> None:
        if packet.haslayer(DNS) and packet.haslayer(UDP):
            captured_packets.append(packet)

    logger.info(
        "Capturing DNS traffic for %s seconds%s...",
        duration,
        f" on interface {iface}" if iface else "",
    )
    try:
        sniff(filter="udp port 53", iface=iface, prn=packet_handler, store=False, timeout=duration)
    except PermissionError:
        logger.error(
            "Permission denied while capturing packets. Raw packet capture requires "
            "elevated privileges - try running with sudo, or grant CAP_NET_RAW."
        )
        raise
    except OSError as exc:
        logger.error("Failed to start packet capture (check the interface name): %s", exc)
        raise

    if captured_packets:
        wrpcap(pcap_file, captured_packets)
        logger.info("Captured %d DNS packet(s), saved to %s", len(captured_packets), pcap_file)
    else:
        logger.warning("No DNS packets captured during the %ss capture window.", duration)

    return captured_packets


def analyze_pcap(
    pcap_file: str,
    json_file: str,
    report_file: str,
    settings: Optional[DetectionSettings] = None,
) -> List[Dict[str, Any]]:
    """Analyze the captured DNS packets and save details to JSON and a PDF report."""
    settings = settings or DetectionSettings()

    pcap_path = Path(pcap_file)
    if not pcap_path.exists():
        raise FileNotFoundError(f"Capture file not found: {pcap_file}")

    logger.info("Analyzing captured DNS traffic from %s...", pcap_file)
    try:
        captured_packets = rdpcap(str(pcap_path))
    except Exception as exc:
        raise ValueError(f"Failed to read pcap file {pcap_file}: {exc}") from exc

    records: List[Dict[str, Any]] = []
    skipped = 0
    for packet in captured_packets:
        if not (packet.haslayer(DNS) and packet.haslayer(UDP)):
            continue
        record = build_dns_record(packet, settings.entropy_threshold)
        if record is None:
            skipped += 1
            continue
        records.append(record)

    if skipped:
        logger.warning("Skipped %d DNS packet(s) without an IP layer.", skipped)

    records = apply_detection_signals(records, settings)

    c = canvas.Canvas(report_file, pagesize=letter)
    c.setFont("Helvetica-Bold", 14)
    c.drawCentredString(300, 770, "DNS Traffic Analysis Report")
    c.setFont("Helvetica", 12)
    y_position = MARGIN_TOP

    for record in records:
        formatted_flags = format_flags(record["flags"])
        flag_lines = formatted_flags.split("\n")
        z_score_text = (
            f"{record['entropy_z_score']:.2f}" if record["entropy_z_score"] is not None else "N/A"
        )

        c.setFont("Helvetica-Bold", 12)
        c.drawString(MARGIN_LEFT, y_position, f"Query: {record['query']}")
        c.setFont("Helvetica", 12)
        c.drawString(
            MARGIN_LEFT,
            y_position - LINE_SPACING,
            f"Source: {record['source_ip']} -> Destination: {record['destination_ip']}",
        )
        c.drawString(
            MARGIN_LEFT,
            y_position - 2 * LINE_SPACING,
            f"Entropy: {record['entropy']:.4f} (z-score: {z_score_text})",
        )
        c.drawString(MARGIN_LEFT, y_position - 3 * LINE_SPACING, "Flags:")
        for i, line in enumerate(flag_lines):
            c.drawString(MARGIN_LEFT + 20, y_position - (4 + i) * LINE_SPACING, line)
        c.setFillColor(colors.red)
        c.drawString(
            MARGIN_LEFT,
            y_position - (5 + len(flag_lines)) * LINE_SPACING,
            f"Remark: {record['remark']}",
        )
        c.setFillColor(colors.black)
        c.drawString(
            MARGIN_LEFT,
            y_position - (6 + len(flag_lines)) * LINE_SPACING,
            "-------------------------------------------------",
        )
        y_position -= 140 + (len(flag_lines) * LINE_SPACING)
        if y_position < 100:
            c.showPage()
            c.setFont("Helvetica", 12)
            y_position = MARGIN_TOP

    c.save()

    with open(json_file, "w") as f:
        json.dump(records, f, indent=4)
    logger.info("Analysis results saved to %s", json_file)
    logger.info("Report saved to %s", report_file)

    return records


def load_config(path: Optional[str]) -> Dict[str, Any]:
    """Load default option values from a JSON config file, if one is given and exists."""
    if not path:
        return {}
    config_path = Path(path)
    if not config_path.exists():
        return {}
    try:
        with open(config_path) as f:
            return json.load(f)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in config file {path}: {exc}") from exc


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse CLI arguments, using a JSON config file (if provided) for defaults.

    Precedence: CLI flags > config file > built-in defaults.
    """
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument(
        "-c", "--config", default=None,
        help="Path to a JSON config file providing default values for the other options.",
    )
    pre_args, _ = pre_parser.parse_known_args(argv)
    config = load_config(pre_args.config)

    parser = argparse.ArgumentParser(
        parents=[pre_parser],
        description="Capture and analyze DNS traffic for anomalies such as DNS tunneling and DGA-generated domains.",
    )
    parser.add_argument(
        "-d", "--duration", type=int, default=config.get("duration", 60),
        help="Duration to capture DNS traffic, in seconds (default: 60)",
    )
    parser.add_argument(
        "-i", "--iface", default=config.get("iface"),
        help="Network interface to capture on (default: scapy's default interface)",
    )
    parser.add_argument(
        "-o", "--output-dir", default=config.get("output_dir", "."),
        help="Directory to write output files to (default: current directory)",
    )
    parser.add_argument(
        "--entropy-threshold", type=float,
        default=config.get("entropy_threshold", DEFAULT_ENTROPY_THRESHOLD),
        help=f"Entropy above which a domain is flagged as high-entropy (default: {DEFAULT_ENTROPY_THRESHOLD})",
    )
    parser.add_argument(
        "--z-score-threshold", type=float,
        default=config.get("z_score_threshold", DEFAULT_Z_SCORE_THRESHOLD),
        help=(
            "Per-host entropy z-score above which a query is flagged as anomalous "
            f"(default: {DEFAULT_Z_SCORE_THRESHOLD})"
        ),
    )
    parser.add_argument(
        "--min-baseline-samples", type=int,
        default=config.get("min_baseline_samples", DEFAULT_MIN_BASELINE_SAMPLES),
        help=(
            "Minimum queries from a host before it gets its own entropy baseline "
            f"(default: {DEFAULT_MIN_BASELINE_SAMPLES})"
        ),
    )
    parser.add_argument(
        "--burst-window-seconds", type=int,
        default=config.get("burst_window_seconds", DEFAULT_BURST_WINDOW_SECONDS),
        help=(
            "Time window for subdomain-burst (DNS tunneling) detection, in seconds "
            f"(default: {DEFAULT_BURST_WINDOW_SECONDS})"
        ),
    )
    parser.add_argument(
        "--burst-unique-subdomain-threshold", type=int,
        default=config.get("burst_unique_subdomain_threshold", DEFAULT_BURST_UNIQUE_SUBDOMAIN_THRESHOLD),
        help=(
            "Unique subdomains under one parent domain within the burst window to flag as "
            f"possible tunneling (default: {DEFAULT_BURST_UNIQUE_SUBDOMAIN_THRESHOLD})"
        ),
    )
    parser.add_argument(
        "--nxdomain-ratio-threshold", type=float,
        default=config.get("nxdomain_ratio_threshold", DEFAULT_NXDOMAIN_RATIO_THRESHOLD),
        help=(
            "Fraction of NXDOMAIN responses to a client above which it's flagged as a "
            f"possible DGA client (default: {DEFAULT_NXDOMAIN_RATIO_THRESHOLD})"
        ),
    )
    parser.add_argument(
        "--min-nxdomain-samples", type=int,
        default=config.get("min_nxdomain_samples", DEFAULT_MIN_NXDOMAIN_SAMPLES),
        help=(
            "Minimum responses to a client before its NXDOMAIN ratio is evaluated "
            f"(default: {DEFAULT_MIN_NXDOMAIN_SAMPLES})"
        ),
    )
    parser.add_argument(
        "--pcap-file", default=config.get("pcap_file", "dns_capture.pcap"),
        help="Filename for the captured pcap (default: dns_capture.pcap)",
    )
    parser.add_argument(
        "--json-file", default=config.get("json_file", "output.json"),
        help="Filename for the JSON analysis output (default: output.json)",
    )
    parser.add_argument(
        "--report-file", default=config.get("report_file", "dns_report.pdf"),
        help="Filename for the PDF report (default: dns_report.pdf)",
    )
    parser.add_argument(
        "--log-level", default=config.get("log_level", "INFO"),
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )
    return parser.parse_args(argv)


def settings_from_args(args: argparse.Namespace) -> DetectionSettings:
    return DetectionSettings(
        entropy_threshold=args.entropy_threshold,
        z_score_threshold=args.z_score_threshold,
        min_baseline_samples=args.min_baseline_samples,
        burst_window_seconds=args.burst_window_seconds,
        burst_unique_subdomain_threshold=args.burst_unique_subdomain_threshold,
        nxdomain_ratio_threshold=args.nxdomain_ratio_threshold,
        min_nxdomain_samples=args.min_nxdomain_samples,
    )


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(asctime)s [%(levelname)s] %(message)s")
    logger.info("DNS Analyzer - developed by CipherxHub")
    logger.debug("Detection settings: %s", asdict(settings_from_args(args)))

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    pcap_file = str(output_dir / args.pcap_file)
    json_file = str(output_dir / args.json_file)
    report_file = str(output_dir / args.report_file)

    try:
        packets = capture_dns_packets(args.duration, args.iface, pcap_file)
    except (PermissionError, OSError):
        return 1

    if not packets:
        logger.warning("No DNS traffic captured; skipping analysis.")
        return 0

    try:
        analyze_pcap(pcap_file, json_file, report_file, settings_from_args(args))
    except (FileNotFoundError, ValueError) as exc:
        logger.error(str(exc))
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
