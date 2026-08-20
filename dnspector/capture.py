"""DNS packet capture."""

import logging
from typing import Callable, List, Optional

from scapy.all import DNS, UDP, Packet, sniff, wrpcap

logger = logging.getLogger(__name__)


def capture_dns_packets(
    duration: int,
    iface: Optional[str],
    pcap_file: str,
    on_packet: Optional[Callable[[Packet], None]] = None,
) -> List[Packet]:
    """Capture DNS packets for a user-defined duration and save them to a pcap file.

    duration <= 0 means capture indefinitely, until interrupted (Ctrl+C) -
    scapy's sniff() catches KeyboardInterrupt internally and returns the
    packets captured so far, so this stops cleanly rather than crashing.

    If on_packet is given, it's called synchronously for every captured
    DNS+UDP packet as it arrives (used by the live/streaming pipeline in
    dnspector.live to run detection inline instead of only after the
    whole capture window ends). It runs on the capture thread, so it
    should be fast - anything slow (e.g. a webhook call) will delay
    processing of subsequent packets.
    """
    captured_packets: List[Packet] = []

    def packet_handler(packet: Packet) -> None:
        if packet.haslayer(DNS) and packet.haslayer(UDP):
            captured_packets.append(packet)
            if on_packet is not None:
                on_packet(packet)

    logger.info(
        "Capturing DNS traffic %s%s...",
        f"for {duration} seconds" if duration > 0 else "indefinitely (until interrupted)",
        f" on interface {iface}" if iface else "",
    )
    try:
        sniff(
            filter="udp port 53",
            iface=iface,
            prn=packet_handler,
            store=False,
            timeout=duration if duration > 0 else None,
        )
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
        logger.warning("No DNS packets captured.")

    return captured_packets
