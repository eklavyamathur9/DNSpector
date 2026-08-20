import pytest
from scapy.all import DNS, DNSQR, IP, UDP

import dns_analyzer.capture as capture_module
from dns_analyzer.capture import capture_dns_packets


def _dns_packet():
    return IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=5000, dport=53) / DNS(qr=0, qd=DNSQR(qname="example.com"))


def _non_dns_packet():
    return IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=5000, dport=80)


class TestCaptureDnsPackets:
    def test_filters_to_dns_udp_packets_only(self, monkeypatch, tmp_path):
        dns_pkt = _dns_packet()
        non_dns_pkt = _non_dns_packet()

        def fake_sniff(**kwargs):
            kwargs["prn"](dns_pkt)
            kwargs["prn"](non_dns_pkt)

        monkeypatch.setattr(capture_module, "sniff", fake_sniff)
        packets = capture_dns_packets(duration=5, iface=None, pcap_file=str(tmp_path / "out.pcap"))
        assert len(packets) == 1

    def test_saves_captured_packets_to_pcap_file(self, monkeypatch, tmp_path):
        def fake_sniff(**kwargs):
            kwargs["prn"](_dns_packet())

        monkeypatch.setattr(capture_module, "sniff", fake_sniff)
        pcap_path = tmp_path / "out.pcap"
        capture_dns_packets(duration=5, iface=None, pcap_file=str(pcap_path))
        assert pcap_path.exists()

    def test_on_packet_callback_invoked_for_each_dns_packet(self, monkeypatch, tmp_path):
        packets = [_dns_packet(), _dns_packet()]

        def fake_sniff(**kwargs):
            for p in packets:
                kwargs["prn"](p)

        monkeypatch.setattr(capture_module, "sniff", fake_sniff)
        seen = []
        capture_dns_packets(duration=5, iface=None, pcap_file=str(tmp_path / "out.pcap"), on_packet=seen.append)
        assert len(seen) == 2

    def test_on_packet_not_called_for_non_dns_traffic(self, monkeypatch, tmp_path):
        def fake_sniff(**kwargs):
            kwargs["prn"](_non_dns_packet())

        monkeypatch.setattr(capture_module, "sniff", fake_sniff)
        seen = []
        capture_dns_packets(duration=5, iface=None, pcap_file=str(tmp_path / "out.pcap"), on_packet=seen.append)
        assert seen == []

    def test_zero_duration_passes_none_timeout_for_indefinite_capture(self, monkeypatch, tmp_path):
        captured_kwargs = {}

        def fake_sniff(**kwargs):
            captured_kwargs.update(kwargs)

        monkeypatch.setattr(capture_module, "sniff", fake_sniff)
        capture_dns_packets(duration=0, iface=None, pcap_file=str(tmp_path / "out.pcap"))
        assert captured_kwargs["timeout"] is None

    def test_negative_duration_also_passes_none_timeout(self, monkeypatch, tmp_path):
        captured_kwargs = {}

        def fake_sniff(**kwargs):
            captured_kwargs.update(kwargs)

        monkeypatch.setattr(capture_module, "sniff", fake_sniff)
        capture_dns_packets(duration=-1, iface=None, pcap_file=str(tmp_path / "out.pcap"))
        assert captured_kwargs["timeout"] is None

    def test_positive_duration_passed_through_as_timeout(self, monkeypatch, tmp_path):
        captured_kwargs = {}

        def fake_sniff(**kwargs):
            captured_kwargs.update(kwargs)

        monkeypatch.setattr(capture_module, "sniff", fake_sniff)
        capture_dns_packets(duration=30, iface=None, pcap_file=str(tmp_path / "out.pcap"))
        assert captured_kwargs["timeout"] == 30

    def test_permission_error_is_reraised(self, monkeypatch, tmp_path):
        def fake_sniff(**kwargs):
            raise PermissionError("nope")

        monkeypatch.setattr(capture_module, "sniff", fake_sniff)
        with pytest.raises(PermissionError):
            capture_dns_packets(duration=5, iface=None, pcap_file=str(tmp_path / "out.pcap"))

    def test_os_error_is_reraised(self, monkeypatch, tmp_path):
        def fake_sniff(**kwargs):
            raise OSError("no such interface")

        monkeypatch.setattr(capture_module, "sniff", fake_sniff)
        with pytest.raises(OSError):
            capture_dns_packets(duration=5, iface="bogus0", pcap_file=str(tmp_path / "out.pcap"))

    def test_no_packets_captured_returns_empty_list_without_writing_pcap(self, monkeypatch, tmp_path):
        def fake_sniff(**kwargs):
            pass

        monkeypatch.setattr(capture_module, "sniff", fake_sniff)
        pcap_path = tmp_path / "out.pcap"
        packets = capture_dns_packets(duration=5, iface=None, pcap_file=str(pcap_path))
        assert packets == []
        assert not pcap_path.exists()
