"""CSV and STIX export (Phase 5 - interoperability with a real SOC).

Both of these are pure "records in, file out" converters with no
network I/O - the SIEM-forwarding counterpart that *does* touch the
network (syslog/CEF) lives in syslog_forwarder.py instead, mirroring
the pure-output (report.py) vs. network-side-effect (alerting.py)
split already used elsewhere in this package.
"""

import csv
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

CSV_FIELDNAMES = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "query",
    "registrable_domain",
    "subdomain",
    "entropy",
    "entropy_z_score",
    "qdcount",
    "ancount",
    "nscount",
    "arcount",
    "flags_qr",
    "flags_opcode",
    "flags_aa",
    "flags_tc",
    "flags_rd",
    "flags_ra",
    "flags_rcode",
    "subdomain_burst",
    "subdomain_burst_unique_count",
    "host_nxdomain_ratio",
    "threat_intel_is_malicious",
    "threat_intel_source",
    "threat_intel_detail",
    "severity",
    "remark",
]

STIX_SPEC_VERSION = "2.1"


def flatten_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten one analysis record's nested "flags"/"threat_intel" dicts
    into a flat row matching CSV_FIELDNAMES - CSV has no concept of a
    nested value, so this has to happen somewhere, and doing it as a
    small pure function keeps it independently testable from the actual
    file-writing in generate_csv_report().
    """
    flags = record.get("flags") or {}
    threat_intel = record.get("threat_intel") or {}
    return {
        "timestamp": record.get("timestamp"),
        "source_ip": record.get("source_ip"),
        "destination_ip": record.get("destination_ip"),
        "query": record.get("query"),
        "registrable_domain": record.get("registrable_domain"),
        "subdomain": record.get("subdomain"),
        "entropy": record.get("entropy"),
        "entropy_z_score": record.get("entropy_z_score"),
        "qdcount": record.get("qdcount"),
        "ancount": record.get("ancount"),
        "nscount": record.get("nscount"),
        "arcount": record.get("arcount"),
        "flags_qr": flags.get("qr"),
        "flags_opcode": flags.get("opcode"),
        "flags_aa": flags.get("aa"),
        "flags_tc": flags.get("tc"),
        "flags_rd": flags.get("rd"),
        "flags_ra": flags.get("ra"),
        "flags_rcode": flags.get("rcode"),
        "subdomain_burst": record.get("subdomain_burst"),
        "subdomain_burst_unique_count": record.get("subdomain_burst_unique_count"),
        "host_nxdomain_ratio": record.get("host_nxdomain_ratio"),
        "threat_intel_is_malicious": threat_intel.get("is_malicious"),
        "threat_intel_source": threat_intel.get("source"),
        "threat_intel_detail": threat_intel.get("detail"),
        "severity": record.get("severity"),
        "remark": record.get("remark"),
    }


def generate_csv_report(records: List[Dict[str, Any]], csv_file: str) -> None:
    """Write records to a flat CSV file, for easy pivoting in a
    spreadsheet or SIEM CSV-ingest pipeline."""
    with open(csv_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()
        for record in records:
            writer.writerow(flatten_record(record))


def _stix_indicator_id(domain: str) -> str:
    """Deterministic STIX id (UUID5, keyed off the domain via the
    standard DNS namespace) so re-running an export for the same domain
    produces the same indicator id instead of a fresh one every time.
    """
    return f"indicator--{uuid.uuid5(uuid.NAMESPACE_DNS, domain)}"


def build_stix_bundle(
    records: List[Dict[str, Any]],
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> Dict[str, Any]:
    """Build a STIX 2.1 bundle with one Indicator object per unique
    registrable domain a threat-intel provider confirmed as malicious.

    Deliberately minimal - a real STIX producer would also set
    created_by_ref (an Identity object for this tool), object_marking_
    refs (e.g. a TLP marking), and likely a relationship to a Malware or
    Threat-Actor SDO. Scoped down here to what's directly derivable from
    a ThreatIntelVerdict without inventing data this tool doesn't have.
    """
    seen: Dict[str, Dict[str, Any]] = {}
    for record in records:
        threat_intel = record.get("threat_intel")
        if not threat_intel or not threat_intel.get("is_malicious"):
            continue
        domain = record.get("registrable_domain")
        if not domain or domain in seen:
            continue
        seen[domain] = threat_intel

    timestamp = now_fn().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    objects = []
    for domain, threat_intel in seen.items():
        objects.append({
            "type": "indicator",
            "spec_version": STIX_SPEC_VERSION,
            "id": _stix_indicator_id(domain),
            "created": timestamp,
            "modified": timestamp,
            "name": f"Malicious domain: {domain}",
            "description": f"Flagged by {threat_intel.get('source')}: {threat_intel.get('detail')}",
            "indicator_types": ["malicious-activity"],
            "pattern": f"[domain-name:value = '{domain}']",
            "pattern_type": "stix",
            "valid_from": timestamp,
        })

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def write_stix_bundle(
    records: List[Dict[str, Any]],
    stix_file: str,
    now_fn: Optional[Callable[[], datetime]] = None,
) -> None:
    bundle = build_stix_bundle(records, now_fn) if now_fn else build_stix_bundle(records)
    with open(stix_file, "w") as f:
        json.dump(bundle, f, indent=2)
