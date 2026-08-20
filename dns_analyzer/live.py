"""Live/streaming capture-and-detect pipeline (Phase 4).

Unlike analysis.analyze_pcap() (a full two/three-pass batch analysis run
after capture completes), this runs detection - and alerting - inline as
each packet arrives, via LiveDetectionEngine's incremental algorithms
instead of detection.py's batch functions. The full record list is still
accumulated and written to JSON/PDF at the end, exactly like batch mode,
so both modes produce the same *shape* of output - live mode just gets
you per-packet alerts (and a causally-online statistical baseline - see
DOCUMENTATION.md) during the capture instead of only after it ends.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from scapy.all import Packet

from dns_analyzer.alerting import WebhookAlerter, classify_severity
from dns_analyzer.capture import capture_dns_packets
from dns_analyzer.detection import DetectionSettings, LiveDetectionEngine, build_dns_record
from dns_analyzer.report import generate_pdf_report
from dns_analyzer.threat_intel import ThreatIntelChecker, annotate_threat_intel

logger = logging.getLogger(__name__)


def capture_and_detect_live(
    duration: int,
    iface: Optional[str],
    pcap_file: str,
    json_file: str,
    report_file: str,
    settings: Optional[DetectionSettings] = None,
    threat_intel_checker: Optional[ThreatIntelChecker] = None,
    alerter: Optional[WebhookAlerter] = None,
) -> List[Dict[str, Any]]:
    """Capture DNS traffic and run detection (and optional threat-intel /
    alerting) on each packet as it arrives, then write the same JSON/PDF
    output as the batch pipeline once capture ends.
    """
    settings = settings or DetectionSettings()
    engine = LiveDetectionEngine(settings)
    records: List[Dict[str, Any]] = []

    def process_packet(packet: Packet) -> None:
        record = build_dns_record(packet, settings.entropy_threshold)
        if record is None:
            return

        record = engine.process(record)
        if threat_intel_checker is not None:
            annotate_threat_intel(record, threat_intel_checker)
        record["severity"] = classify_severity(record)
        records.append(record)

        if alerter is not None:
            severity = alerter.maybe_alert(record)
            if severity:
                logger.warning("[%s] %s -> %s", severity.upper(), record["query"], record["remark"])

    packets = capture_dns_packets(duration, iface, pcap_file, on_packet=process_packet)
    if not packets:
        return records

    generate_pdf_report(records, report_file)
    with open(json_file, "w") as f:
        json.dump(records, f, indent=4)
    logger.info("Analysis results saved to %s", json_file)
    logger.info("Report saved to %s", report_file)

    return records
