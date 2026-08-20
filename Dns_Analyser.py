import argparse
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from scapy.all import DNS, DNSQR, IP, UDP, Packet, rdpcap, sniff, wrpcap

logger = logging.getLogger("dns_analyzer")

DEFAULT_ENTROPY_THRESHOLD = 3.5
MARGIN_LEFT = 50
MARGIN_TOP = 750
LINE_SPACING = 20

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


def calculate_entropy(domain: str) -> float:
    """Calculate Shannon entropy of a domain name."""
    if not domain:
        return 0.0
    prob = [float(domain.count(c)) / len(domain) for c in set(domain)]
    return -sum(p * np.log2(p) for p in prob)


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
) -> str:
    """Generate remarks based on entropy and DNS flags."""
    if entropy > entropy_threshold:
        return "High entropy domain name - Possible DGA or DNS Tunneling"
    if flags["rcode"] == "REFUSED":
        return "DNS query refused by the server"
    if flags["qr"] == "RESPONSE" and flags["rcode"] != "NOERROR":
        return "Unsuccessful DNS response - Possible misconfiguration or attack"
    return "Normal query"


def build_dns_record(packet: Packet, entropy_threshold: float) -> Optional[Dict[str, Any]]:
    """Build a structured analysis record from a captured DNS packet.

    Returns None if the packet has no IP layer (e.g. non-IPv4 traffic),
    since source/destination cannot be determined in that case.
    """
    if not packet.haslayer(IP):
        return None

    dns = packet[DNS]
    dns_query = (
        packet[DNSQR].qname.decode("utf-8") if packet.haslayer(DNSQR) else "Unknown"
    )
    entropy = calculate_entropy(dns_query)
    flags = parse_dns_flags(dns)
    remark = generate_remark(entropy, flags, entropy_threshold)

    return {
        "source_ip": packet[IP].src,
        "destination_ip": packet[IP].dst,
        "query": dns_query,
        "entropy": entropy,
        "qdcount": dns.qdcount,
        "ancount": dns.ancount,
        "nscount": dns.nscount,
        "arcount": dns.arcount,
        "flags": flags,
        "remark": remark,
    }


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
    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
) -> List[Dict[str, Any]]:
    """Analyze the captured DNS packets and save details to JSON and a PDF report."""
    pcap_path = Path(pcap_file)
    if not pcap_path.exists():
        raise FileNotFoundError(f"Capture file not found: {pcap_file}")

    logger.info("Analyzing captured DNS traffic from %s...", pcap_file)
    try:
        captured_packets = rdpcap(str(pcap_path))
    except Exception as exc:
        raise ValueError(f"Failed to read pcap file {pcap_file}: {exc}") from exc

    analysis_results: List[Dict[str, Any]] = []
    skipped = 0

    c = canvas.Canvas(report_file, pagesize=letter)
    c.setFont("Helvetica-Bold", 14)
    c.drawCentredString(300, 770, "DNS Traffic Analysis Report")
    c.setFont("Helvetica", 12)
    y_position = MARGIN_TOP

    for packet in captured_packets:
        if not (packet.haslayer(DNS) and packet.haslayer(UDP)):
            continue

        record = build_dns_record(packet, entropy_threshold)
        if record is None:
            skipped += 1
            continue
        analysis_results.append(record)

        formatted_flags = format_flags(record["flags"])
        flag_lines = formatted_flags.split("\n")

        c.setFont("Helvetica-Bold", 12)
        c.drawString(MARGIN_LEFT, y_position, f"Query: {record['query']}")
        c.setFont("Helvetica", 12)
        c.drawString(
            MARGIN_LEFT,
            y_position - LINE_SPACING,
            f"Source: {record['source_ip']} -> Destination: {record['destination_ip']}",
        )
        c.drawString(MARGIN_LEFT, y_position - 2 * LINE_SPACING, f"Entropy: {record['entropy']:.4f}")
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

    if skipped:
        logger.warning("Skipped %d DNS packet(s) without an IP layer.", skipped)

    with open(json_file, "w") as f:
        json.dump(analysis_results, f, indent=4)
    logger.info("Analysis results saved to %s", json_file)
    logger.info("Report saved to %s", report_file)

    return analysis_results


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


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(asctime)s [%(levelname)s] %(message)s")
    logger.info("DNS Analyzer - developed by CipherxHub")

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
        analyze_pcap(pcap_file, json_file, report_file, args.entropy_threshold)
    except (FileNotFoundError, ValueError) as exc:
        logger.error(str(exc))
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
