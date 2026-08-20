from dns_analyzer.alerting import (
    AlertSettings,
    WebhookAlerter,
    classify_severity,
    format_alert_message,
)


def make_record(remark="Normal query", threat_intel=None, **overrides):
    record = {
        "query": "evil.com.",
        "source_ip": "10.0.0.1",
        "destination_ip": "8.8.8.8",
        "remark": remark,
        "threat_intel": threat_intel,
    }
    record.update(overrides)
    return record


class TestClassifySeverity:
    def test_normal_query_is_info(self):
        assert classify_severity(make_record(remark="Normal query")) == "info"

    def test_high_entropy_dga_remark_is_high(self):
        record = make_record(remark="High entropy domain name - Possible DGA or DNS Tunneling")
        assert classify_severity(record) == "high"

    def test_z_score_anomaly_remark_is_high(self):
        record = make_record(remark="Entropy anomalous for this host (z=4.20) - Possible DGA or DNS Tunneling")
        assert classify_severity(record) == "high"

    def test_burst_note_is_high(self):
        record = make_record(
            remark="Normal query | 20 unique subdomains under evil.com within 60s - possible DNS tunneling"
        )
        assert classify_severity(record) == "high"

    def test_nxdomain_ratio_note_is_high(self):
        record = make_record(
            remark=(
                "Unsuccessful DNS response | host 1.2.3.4 has a high NXDOMAIN ratio "
                "(90% of 10 responses) - possible DGA client"
            )
        )
        assert classify_severity(record) == "high"

    def test_refused_query_is_medium(self):
        assert classify_severity(make_record(remark="DNS query refused by the server")) == "medium"

    def test_unsuccessful_response_is_medium(self):
        record = make_record(remark="Unsuccessful DNS response - Possible misconfiguration or attack")
        assert classify_severity(record) == "medium"

    def test_confirmed_threat_intel_match_is_critical_even_with_normal_remark(self):
        record = make_record(
            remark="Normal query | domain matches urlhaus threat intel: 3 malicious URL(s) on record",
            threat_intel={"is_malicious": True, "source": "urlhaus"},
        )
        assert classify_severity(record) == "critical"

    def test_threat_intel_clean_verdict_does_not_override_lower_severity(self):
        record = make_record(remark="Normal query", threat_intel={"is_malicious": False, "source": None})
        assert classify_severity(record) == "info"

    def test_critical_takes_precedence_over_high_signals(self):
        record = make_record(
            remark="High entropy domain name - Possible DGA or DNS Tunneling",
            threat_intel={"is_malicious": True, "source": "urlhaus"},
        )
        assert classify_severity(record) == "critical"


class TestFormatAlertMessage:
    def test_includes_severity_query_and_remark(self):
        record = make_record(remark="High entropy domain name - Possible DGA or DNS Tunneling", query="evil.com.")
        message = format_alert_message(record, "high")
        assert "HIGH" in message
        assert "evil.com." in message
        assert "Possible DGA" in message


class TestWebhookAlerter:
    def test_sends_alert_when_severity_meets_minimum(self):
        sent = []
        settings = AlertSettings(enabled=True, webhook_url="https://example.invalid/hook", min_severity="high")
        alerter = WebhookAlerter(settings, sender=lambda url, payload, timeout: sent.append((url, payload)))

        record = make_record(remark="High entropy domain name - Possible DGA or DNS Tunneling")
        severity = alerter.maybe_alert(record)

        assert severity == "high"
        assert len(sent) == 1
        url, payload = sent[0]
        assert url == "https://example.invalid/hook"
        assert "text" in payload and "content" in payload

    def test_does_not_send_when_below_minimum_severity(self):
        sent = []
        settings = AlertSettings(enabled=True, webhook_url="https://example.invalid/hook", min_severity="critical")
        alerter = WebhookAlerter(settings, sender=lambda url, payload, timeout: sent.append(1))

        severity = alerter.maybe_alert(make_record(remark="DNS query refused by the server"))

        assert severity is None
        assert sent == []

    def test_does_not_send_when_disabled(self):
        sent = []
        settings = AlertSettings(enabled=False, webhook_url="https://example.invalid/hook", min_severity="info")
        alerter = WebhookAlerter(settings, sender=lambda url, payload, timeout: sent.append(1))

        severity = alerter.maybe_alert(make_record(remark="Normal query"))

        assert severity is None
        assert sent == []

    def test_does_not_send_when_no_webhook_url_configured(self):
        sent = []
        settings = AlertSettings(enabled=True, webhook_url=None, min_severity="info")
        alerter = WebhookAlerter(settings, sender=lambda url, payload, timeout: sent.append(1))

        alerter.maybe_alert(make_record(remark="Normal query"))

        assert sent == []

    def test_sender_error_is_swallowed_and_still_reports_severity(self):
        def failing_sender(url, payload, timeout):
            raise TimeoutError("webhook unreachable")

        settings = AlertSettings(enabled=True, webhook_url="https://example.invalid/hook", min_severity="high")
        alerter = WebhookAlerter(settings, sender=failing_sender)

        severity = alerter.maybe_alert(
            make_record(remark="High entropy domain name - Possible DGA or DNS Tunneling")
        )

        # the alert attempt still "counts" (severity reported) even though sending failed -
        # a webhook outage should never look like "nothing was wrong"
        assert severity == "high"
