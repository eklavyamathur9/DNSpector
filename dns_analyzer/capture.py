"""DNS packet capture."""

import logging
from typing import List, Optional

from scapy.all import DNS, UDP, Packet, sniff, wrpcap

logger = logging.getLogger(__name__)


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
