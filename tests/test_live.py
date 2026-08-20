import csv
import json

import pytest
from scapy.all import DNS, DNSQR, IP, UDP

import dnspector.capture as capture_module
from dnspector.alerting import AlertSettings, WebhookAlerter
from dnspector.detection import DetectionSettings
from dnspector.live import capture_and_detect_live
from dnspector.syslog_forwarder import SyslogCefForwarder, SyslogSettings
from dnspector.threat_intel import OpenPhishFeed, ThreatIntelChecker, ThreatIntelSettings


def _query(src, qname, t):
    pkt = IP(src=src, dst="8.8.8.8") / UDP(sport=5000, dport=53) / DNS(qr=0, qd=DNSQR(qname=qname))
    pkt.time = t
    return pkt


class TestCaptureAndDetectLive:
    def test_processes_packets_inline_and_writes_output(self, monkeypatch, tmp_path):
        packets = [
            _query("192.168.1.10", "google.com", t=1000.0),
            _query("192.168.1.10", "github.com", t=1001.0),
        ]

        def fake_sniff(**kwargs):
            for p in packets:
                kwargs["prn"](p)

        monkeypatch.setattr(capture_module, "sniff", fake_sniff)

        json_file = tmp_path / "out.json"
        report_file = tmp_path / "out.pdf"
        records = capture_and_detect_live(
            duration=5, iface=None,
            pcap_file=str(tmp_path / "capture.pcap"),
            json_file=str(json_file), report_file=str(report_file),
            settings=DetectionSettings(),
        )

        assert len(records) == 2
        assert json_file.exists()
        assert report_file.exists()
        assert json.loads(json_file.read_text()) == records

    def test_burst_detection_fires_inline_as_packets_arrive(self, monkeypatch, tmp_path):
        packets = [
            _query("192.168.1.50", f"chunk{i}abcdefgh.tunnel.evil.com", t=1000.0 + i) for i in range(6)
        ]

        def fake_sniff(**kwargs):
            for p in packets:
                kwargs["prn"](p)

        monkeypatch.setattr(capture_module, "sniff", fake_sniff)

        settings = DetectionSettings(
            entropy_threshold=10.0, burst_window_seconds=60, burst_unique_subdomain_threshold=5
        )
        records = capture_and_detect_live(
            duration=5, iface=None,
            pcap_file=str(tmp_path / "capture.pcap"),
            json_file=str(tmp_path / "out.json"), report_file=str(tmp_path / "out.pdf"),
            settings=settings,
        )

        # the burst threshold (5 unique) is only reached on the 5th distinct
        # subdomain - earlier records shouldn't be flagged, later ones should
        assert not records[3]["subdomain_burst"]
        assert records[4]["subdomain_burst"]
        assert records[5]["subdomain_burst"]

    def test_threat_intel_checked_inline(self, monkeypatch, tmp_path):
        def fake_sniff(**kwargs):
            kwargs["prn"](_query("192.168.1.10", "evil.com", t=1000.0))

        monkeypatch.setattr(capture_module, "sniff", fake_sniff)

        checker = ThreatIntelChecker(
            ThreatIntelSettings(),
            openphish_feed=OpenPhishFeed(fetch_fn=lambda timeout: "https://evil.com/x\n"),
        )

        records = capture_and_detect_live(
            duration=5, iface=None,
            pcap_file=str(tmp_path / "capture.pcap"),
            json_file=str(tmp_path / "out.json"), report_file=str(tmp_path / "out.pdf"),
            settings=DetectionSettings(),
            threat_intel_checker=checker,
        )

        assert records[0]["threat_intel"]["is_malicious"] is True
        assert records[0]["severity"] == "critical"

    def test_alerts_fire_inline_for_flagged_records(self, monkeypatch, tmp_path):
        def fake_sniff(**kwargs):
            # random-looking high-entropy label under a fixed domain -> trips the fixed threshold
            kwargs["prn"](_query("192.168.1.10", "x7q9zk3m1p8wr2nb.evil.com", t=1000.0))
            kwargs["prn"](_query("192.168.1.10", "google.com", t=1001.0))

        monkeypatch.setattr(capture_module, "sniff", fake_sniff)

        sent = []
        alerter = WebhookAlerter(
            AlertSettings(enabled=True, webhook_url="https://example.invalid/hook", min_severity="high"),
            sender=lambda url, payload, timeout: sent.append(payload),
        )

        records = capture_and_detect_live(
            duration=5, iface=None,
            pcap_file=str(tmp_path / "capture.pcap"),
            json_file=str(tmp_path / "out.json"), report_file=str(tmp_path / "out.pdf"),
            settings=DetectionSettings(entropy_threshold=3.5),
            alerter=alerter,
        )

        assert records[0]["severity"] == "high"
        assert records[1]["severity"] == "info"
        assert len(sent) == 1

    def test_no_packets_returns_empty_list_without_writing_output(self, monkeypatch, tmp_path):
        def fake_sniff(**kwargs):
            pass

        monkeypatch.setattr(capture_module, "sniff", fake_sniff)

        json_file = tmp_path / "out.json"
        records = capture_and_detect_live(
            duration=5, iface=None,
            pcap_file=str(tmp_path / "capture.pcap"),
            json_file=str(json_file), report_file=str(tmp_path / "out.pdf"),
        )
        assert records == []
        assert not json_file.exists()

    def test_permission_error_propagates(self, monkeypatch, tmp_path):
        def fake_sniff(**kwargs):
            raise PermissionError("nope")

        monkeypatch.setattr(capture_module, "sniff", fake_sniff)
        with pytest.raises(PermissionError):
            capture_and_detect_live(
                duration=5, iface=None,
                pcap_file=str(tmp_path / "capture.pcap"),
                json_file=str(tmp_path / "out.json"), report_file=str(tmp_path / "out.pdf"),
            )

    def test_csv_export_written_when_csv_file_given(self, monkeypatch, tmp_path):
        def fake_sniff(**kwargs):
            kwargs["prn"](_query("192.168.1.10", "google.com", t=1000.0))

        monkeypatch.setattr(capture_module, "sniff", fake_sniff)

        csv_file = tmp_path / "out.csv"
        capture_and_detect_live(
            duration=5, iface=None,
            pcap_file=str(tmp_path / "capture.pcap"),
            json_file=str(tmp_path / "out.json"), report_file=str(tmp_path / "out.pdf"),
            csv_file=str(csv_file),
        )

        assert csv_file.exists()
        with open(csv_file, newline="") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 1
        assert rows[0]["query"] == "google.com."

    def test_syslog_forwarder_invoked_inline(self, monkeypatch, tmp_path):
        def fake_sniff(**kwargs):
            kwargs["prn"](_query("192.168.1.10", "x7q9zk3m1p8wr2nb.evil.com", t=1000.0))
            kwargs["prn"](_query("192.168.1.10", "google.com", t=1001.0))

        monkeypatch.setattr(capture_module, "sniff", fake_sniff)

        sent = []
        forwarder = SyslogCefForwarder(
            SyslogSettings(enabled=True, host="siem.internal", min_severity="info"),
            sender=sent.append,
        )

        capture_and_detect_live(
            duration=5, iface=None,
            pcap_file=str(tmp_path / "capture.pcap"),
            json_file=str(tmp_path / "out.json"), report_file=str(tmp_path / "out.pdf"),
            settings=DetectionSettings(entropy_threshold=3.5),
            syslog_forwarder=forwarder,
        )

        assert len(sent) == 2
        assert all(message.startswith("CEF:0|") for message in sent)
