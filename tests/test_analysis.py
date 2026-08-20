import time

import pytest
from scapy.all import DNS, DNSQR, IP, UDP, wrpcap

from dns_analyzer.alerting import AlertSettings, WebhookAlerter
from dns_analyzer.analysis import analyze_pcap
from dns_analyzer.detection import DetectionSettings
from dns_analyzer.threat_intel import ThreatIntelChecker, ThreatIntelSettings


def _make_query(src, qname, dst="8.8.8.8", t=None):
    pkt = IP(src=src, dst=dst) / UDP(sport=5000, dport=53) / DNS(qr=0, qd=DNSQR(qname=qname))
    if t is not None:
        pkt.time = t
    return pkt


def _make_nxdomain_response(client_ip, qname, server_ip="8.8.8.8", t=None):
    pkt = IP(src=server_ip, dst=client_ip) / UDP(sport=53, dport=6000) / DNS(qr=1, rcode=3, qd=DNSQR(qname=qname))
    if t is not None:
        pkt.time = t
    return pkt


class TestAnalyzePcapEndToEnd:
    def test_missing_pcap_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            analyze_pcap(
                str(tmp_path / "missing.pcap"), str(tmp_path / "out.json"), str(tmp_path / "out.pdf")
            )

    def test_corrupt_pcap_file_raises_value_error(self, tmp_path):
        bad_pcap = tmp_path / "bad.pcap"
        bad_pcap.write_bytes(b"not a real pcap file")
        with pytest.raises(ValueError):
            analyze_pcap(str(bad_pcap), str(tmp_path / "out.json"), str(tmp_path / "out.pdf"))

    def test_full_pipeline_on_synthetic_capture(self, tmp_path):
        # Fixed (not time.time()) so the burst's timestamps never straddle a
        # 60s window bucket boundary - detect_subdomain_bursts() uses hard
        # windows (see DOCUMENTATION.md known limitations), so a wall-clock
        # base here would make this test flaky depending on when it runs.
        base_t = 1700000000.0
        packets = []

        # normal traffic
        for i, name in enumerate(["google.com", "github.com", "wikipedia.org"]):
            packets.append(_make_query("192.168.1.10", name, t=base_t + i))

        # DNS-tunneling-style burst: many unique subdomains under one parent domain
        for i in range(18):
            packets.append(
                _make_query("192.168.1.50", f"chunk{i}abcdefgh.tunnel.evil-corp.com", t=base_t + i * 0.5)
            )

        # DGA-style NXDOMAIN churn from one client
        for i in range(8):
            packets.append(
                _make_nxdomain_response("192.168.1.99", f"random{i}word.com", t=base_t + i)
            )

        pcap_file = tmp_path / "capture.pcap"
        json_file = tmp_path / "output.json"
        report_file = tmp_path / "report.pdf"
        wrpcap(str(pcap_file), packets)

        records = analyze_pcap(
            str(pcap_file), str(json_file), str(report_file), DetectionSettings()
        )

        assert len(records) == len(packets)
        assert json_file.exists()
        assert report_file.exists()

        burst_records = [r for r in records if r["subdomain_burst"]]
        assert len(burst_records) == 18
        assert burst_records[0]["subdomain_burst_unique_count"] == 18
        assert "tunneling" in burst_records[0]["remark"].lower()
        assert burst_records[0]["severity"] == "high"

        nxdomain_records = [r for r in records if r["host_nxdomain_ratio"]]
        assert len(nxdomain_records) == 8
        assert all(r["host_nxdomain_ratio"] == pytest.approx(1.0) for r in nxdomain_records)
        assert all("nxdomain" in r["remark"].lower() for r in nxdomain_records)
        assert all(r["severity"] == "high" for r in nxdomain_records)

        normal_records = [r for r in records if r["remark"] == "Normal query"]
        assert len(normal_records) == 3
        assert all(r["severity"] == "info" for r in normal_records)

        # threat intel wasn't wired in for this call - every record should reflect that
        assert all(r["threat_intel"] is None for r in records)

    def test_pipeline_with_threat_intel_checker_wired_in(self, tmp_path):
        packets = [_make_query("192.168.1.10", "malicious-domain.com", t=time.time())]
        pcap_file = tmp_path / "capture.pcap"
        wrpcap(str(pcap_file), packets)

        checker = ThreatIntelChecker(
            ThreatIntelSettings(urlhaus_api_key="test-key"),
            urlhaus_fetcher=lambda domain, api_key, timeout: {"query_status": "ok", "url_count": "7"},
        )

        records = analyze_pcap(
            str(pcap_file),
            str(tmp_path / "out.json"),
            str(tmp_path / "out.pdf"),
            DetectionSettings(),
            threat_intel_checker=checker,
        )

        assert records[0]["threat_intel"]["is_malicious"] is True
        assert records[0]["threat_intel"]["source"] == "urlhaus"
        assert "urlhaus" in records[0]["remark"]
        assert records[0]["severity"] == "critical"


class TestAnalyzePcapWithAlerting:
    def test_alerter_fires_for_flagged_records_after_analysis(self, tmp_path):
        packets = [
            _make_query("192.168.1.10", "x7q9zk3m1p8wr2nb.evil.com", t=time.time()),
            _make_query("192.168.1.10", "google.com", t=time.time()),
        ]
        pcap_file = tmp_path / "capture.pcap"
        wrpcap(str(pcap_file), packets)

        sent = []
        alerter = WebhookAlerter(
            AlertSettings(enabled=True, webhook_url="https://example.invalid/hook", min_severity="high"),
            sender=lambda url, payload, timeout: sent.append(payload),
        )

        records = analyze_pcap(
            str(pcap_file), str(tmp_path / "out.json"), str(tmp_path / "out.pdf"),
            DetectionSettings(entropy_threshold=3.5), alerter=alerter,
        )

        assert records[0]["severity"] == "high"
        assert records[1]["severity"] == "info"
        assert len(sent) == 1
