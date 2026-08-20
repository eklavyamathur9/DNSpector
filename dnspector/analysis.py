"""Top-level analysis pipeline: pcap in, JSON + PDF (+ CSV/STIX/syslog) out."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from scapy.all import DNS, UDP, rdpcap

from dnspector.alerting import WebhookAlerter, classify_severity
from dnspector.detection import DetectionSettings, apply_detection_signals, build_dns_record
from dnspector.export import generate_csv_report, write_stix_bundle
from dnspector.report import generate_pdf_report
from dnspector.syslog_forwarder import SyslogCefForwarder
from dnspector.threat_intel import ThreatIntelChecker, apply_threat_intel

logger = logging.getLogger(__name__)


def analyze_pcap(
    pcap_file: str,
    json_file: str,
    report_file: str,
    settings: Optional[DetectionSettings] = None,
    threat_intel_checker: Optional[ThreatIntelChecker] = None,
    alerter: Optional[WebhookAlerter] = None,
    csv_file: Optional[str] = None,
    stix_file: Optional[str] = None,
    syslog_forwarder: Optional[SyslogCefForwarder] = None,
) -> List[Dict[str, Any]]:
    """Analyze the captured DNS packets and save details to JSON, a PDF
    report, and (if requested) CSV/STIX/syslog exports.

    Runs a pipeline over the packets in pcap_file:
      1. build_dns_record() per packet - pure, per-packet parsing.
      2. apply_detection_signals() over the full batch - statistical
         baselining, subdomain-burst detection, NXDOMAIN-ratio tracking.
      3. apply_threat_intel() (only if threat_intel_checker is given) -
         checks each record's registrable domain against threat-intel
         feeds; opt-in, since it sends observed domains to third parties.
      4. Severity classification + optional webhook alerting/syslog
         forwarding - fires once analysis completes. For alerts/forwards
         that go out the moment an anomaly is observed, use live capture
         (dnspector.live) instead.
      5. CSV export (if csv_file given) and a STIX 2.1 indicator bundle
         (if stix_file given), alongside the JSON/PDF output.
    """
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

    if threat_intel_checker is not None:
        logger.info("Checking observed domains against threat-intel feeds...")
        records = apply_threat_intel(records, threat_intel_checker)

    for record in records:
        record["severity"] = classify_severity(record)

    if alerter is not None:
        for record in records:
            severity = alerter.maybe_alert(record)
            if severity:
                logger.warning("[%s] %s -> %s", severity.upper(), record["query"], record["remark"])

    if syslog_forwarder is not None:
        for record in records:
            syslog_forwarder.maybe_forward(record)

    generate_pdf_report(records, report_file)

    if csv_file:
        generate_csv_report(records, csv_file)
        logger.info("CSV export saved to %s", csv_file)

    if stix_file:
        write_stix_bundle(records, stix_file)
        logger.info("STIX bundle saved to %s", stix_file)

    with open(json_file, "w") as f:
        json.dump(records, f, indent=4)
    logger.info("Analysis results saved to %s", json_file)
    logger.info("Report saved to %s", report_file)

    return records
