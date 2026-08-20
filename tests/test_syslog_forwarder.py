from dns_analyzer.syslog_forwarder import (
    SyslogCefForwarder,
    SyslogSettings,
    format_cef,
)


def make_record(remark="Normal query", threat_intel=None, severity=None, **overrides):
    record = {
        "query": "evil.com.",
        "source_ip": "10.0.0.1",
        "destination_ip": "8.8.8.8",
        "registrable_domain": "evil.com",
        "entropy": 3.9,
        "remark": remark,
        "threat_intel": threat_intel,
        "severity": severity,
    }
    record.update(overrides)
    return record


class TestFormatCef:
    def test_includes_cef_header_fields(self):
        message = format_cef(make_record(remark="High entropy domain name - Possible DGA or DNS Tunneling"), "high")
        assert message.startswith("CEF:0|DNSAnalyzer|dns-analyzer|")
        parts = message.split("|")
        assert parts[4] == "dns-anomaly"
        assert parts[6] == "7"  # SEVERITY_TO_CEF["high"]

    def test_includes_extension_fields(self):
        message = format_cef(make_record(), "info")
        assert "src=10.0.0.1" in message
        assert "dst=8.8.8.8" in message
        assert "request=evil.com." in message
        assert "cs1=evil.com" in message

    def test_escapes_pipe_and_backslash_in_header(self):
        # split("|") can't be used to isolate the Name field here since an
        # escaped pipe still contains a literal "|" character - check via
        # substring instead of positional split.
        record = make_record(remark="Weird | remark with \\ backslash")
        message = format_cef(record, "info")
        assert "Weird \\| remark with \\\\ backslash" in message

    def test_escapes_equals_in_extension(self):
        record = make_record(remark="query=value seen")
        message = format_cef(record, "info")
        assert "msg=query\\=value seen" in message

    def test_severity_maps_to_cef_scale(self):
        assert format_cef(make_record(), "critical").split("|")[6] == "10"
        assert format_cef(make_record(), "medium").split("|")[6] == "4"


class TestSyslogCefForwarder:
    def test_forwards_when_severity_meets_minimum(self):
        sent = []
        settings = SyslogSettings(enabled=True, host="siem.internal", min_severity="high")
        forwarder = SyslogCefForwarder(settings, sender=sent.append)

        severity = forwarder.maybe_forward(
            make_record(remark="High entropy domain name - Possible DGA or DNS Tunneling", severity="high")
        )

        assert severity == "high"
        assert len(sent) == 1
        assert sent[0].startswith("CEF:0|")

    def test_does_not_forward_below_minimum_severity(self):
        sent = []
        settings = SyslogSettings(enabled=True, host="siem.internal", min_severity="critical")
        forwarder = SyslogCefForwarder(settings, sender=sent.append)

        severity = forwarder.maybe_forward(make_record(remark="Normal query", severity="info"))

        assert severity is None
        assert sent == []

    def test_default_min_severity_forwards_everything(self):
        sent = []
        settings = SyslogSettings(enabled=True, host="siem.internal")
        forwarder = SyslogCefForwarder(settings, sender=sent.append)

        severity = forwarder.maybe_forward(make_record(remark="Normal query", severity="info"))

        assert severity == "info"
        assert len(sent) == 1

    def test_does_not_forward_when_disabled(self):
        sent = []
        settings = SyslogSettings(enabled=False, host="siem.internal")
        forwarder = SyslogCefForwarder(settings, sender=sent.append)

        forwarder.maybe_forward(make_record(remark="Normal query", severity="info"))

        assert sent == []

    def test_no_op_and_no_real_socket_when_host_unconfigured_and_no_sender(self):
        # constructing this must not attempt to open a real syslog socket
        settings = SyslogSettings(enabled=True, host=None)
        forwarder = SyslogCefForwarder(settings)

        severity = forwarder.maybe_forward(make_record(remark="Normal query", severity="info"))

        assert severity is None

    def test_falls_back_to_classify_severity_when_record_has_none(self):
        sent = []
        settings = SyslogSettings(enabled=True, host="siem.internal", min_severity="high")
        forwarder = SyslogCefForwarder(settings, sender=sent.append)

        record = make_record(remark="High entropy domain name - Possible DGA or DNS Tunneling", severity=None)
        severity = forwarder.maybe_forward(record)

        assert severity == "high"

    def test_sender_error_is_swallowed_and_still_reports_severity(self):
        def failing_sender(message):
            raise TimeoutError("syslog server unreachable")

        settings = SyslogSettings(enabled=True, host="siem.internal", min_severity="info")
        forwarder = SyslogCefForwarder(settings, sender=failing_sender)

        severity = forwarder.maybe_forward(make_record(remark="Normal query", severity="info"))

        assert severity == "info"

    def test_close_is_a_no_op_when_using_injected_sender(self):
        settings = SyslogSettings(enabled=True, host="siem.internal")
        forwarder = SyslogCefForwarder(settings, sender=lambda message: None)
        forwarder.close()  # should not raise
