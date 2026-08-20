import json

from dns_analyzer.cli import (
    alert_settings_from_args,
    parse_args,
    settings_from_args,
    threat_intel_settings_from_args,
)


class TestParseArgs:
    def test_defaults(self):
        args = parse_args([])
        assert args.duration == 60
        assert args.entropy_threshold == 3.5
        assert args.pcap_file == "dns_capture.pcap"
        assert args.log_level == "INFO"

    def test_cli_flags_override_builtin_defaults(self):
        args = parse_args(["--duration", "30", "--entropy-threshold", "4.0", "--iface", "eth0"])
        assert args.duration == 30
        assert args.entropy_threshold == 4.0
        assert args.iface == "eth0"

    def test_config_file_sets_defaults(self, tmp_path):
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"duration": 45}))
        args = parse_args(["--config", str(config_file)])
        assert args.duration == 45

    def test_cli_flag_overrides_config_file(self, tmp_path):
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"duration": 45}))
        args = parse_args(["--config", str(config_file), "--duration", "10"])
        assert args.duration == 10

    def test_new_detection_flags_have_expected_defaults(self):
        args = parse_args([])
        assert args.z_score_threshold == 3.0
        assert args.min_baseline_samples == 5
        assert args.burst_window_seconds == 60
        assert args.burst_unique_subdomain_threshold == 15
        assert args.nxdomain_ratio_threshold == 0.5
        assert args.min_nxdomain_samples == 5

    def test_new_detection_flags_overridable_via_cli(self):
        args = parse_args(["--z-score-threshold", "2.5", "--burst-unique-subdomain-threshold", "10"])
        assert args.z_score_threshold == 2.5
        assert args.burst_unique_subdomain_threshold == 10

    def test_threat_intel_disabled_by_default(self, monkeypatch):
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        args = parse_args([])
        assert args.enable_threat_intel is False
        assert args.virustotal_api_key is None

    def test_threat_intel_enabled_via_flag(self):
        args = parse_args(["--enable-threat-intel"])
        assert args.enable_threat_intel is True

    def test_virustotal_api_key_falls_back_to_env_var(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "env-key")
        args = parse_args([])
        assert args.virustotal_api_key == "env-key"

    def test_virustotal_api_key_cli_flag_overrides_env_var(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "env-key")
        args = parse_args(["--virustotal-api-key", "cli-key"])
        assert args.virustotal_api_key == "cli-key"

    def test_live_disabled_by_default(self):
        assert parse_args([]).live is False

    def test_live_enabled_via_flag(self):
        assert parse_args(["--live"]).live is True

    def test_zero_or_negative_duration_allowed(self):
        # 0/negative means "capture indefinitely" - argparse just needs to accept it
        assert parse_args(["--duration", "0"]).duration == 0
        assert parse_args(["--duration", "-1"]).duration == -1

    def test_alerts_disabled_by_default(self, monkeypatch):
        monkeypatch.delenv("DNS_ANALYZER_WEBHOOK_URL", raising=False)
        args = parse_args([])
        assert args.enable_alerts is False
        assert args.webhook_url is None
        assert args.alert_min_severity == "high"

    def test_alerts_enabled_via_flag(self):
        args = parse_args(["--enable-alerts", "--webhook-url", "https://example.invalid/hook"])
        assert args.enable_alerts is True
        assert args.webhook_url == "https://example.invalid/hook"

    def test_webhook_url_falls_back_to_env_var(self, monkeypatch):
        monkeypatch.setenv("DNS_ANALYZER_WEBHOOK_URL", "https://example.invalid/env-hook")
        args = parse_args([])
        assert args.webhook_url == "https://example.invalid/env-hook"

    def test_webhook_url_cli_flag_overrides_env_var(self, monkeypatch):
        monkeypatch.setenv("DNS_ANALYZER_WEBHOOK_URL", "https://example.invalid/env-hook")
        args = parse_args(["--webhook-url", "https://example.invalid/cli-hook"])
        assert args.webhook_url == "https://example.invalid/cli-hook"

    def test_alert_min_severity_overridable(self):
        args = parse_args(["--alert-min-severity", "critical"])
        assert args.alert_min_severity == "critical"


class TestSettingsFromArgs:
    def test_builds_detection_settings_from_parsed_args(self):
        args = parse_args(["--entropy-threshold", "4.0", "--z-score-threshold", "2.0"])
        settings = settings_from_args(args)
        assert settings.entropy_threshold == 4.0
        assert settings.z_score_threshold == 2.0


class TestThreatIntelSettingsFromArgs:
    def test_builds_threat_intel_settings_from_parsed_args(self, monkeypatch):
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        args = parse_args(["--enable-threat-intel", "--virustotal-api-key", "abc123"])
        settings = threat_intel_settings_from_args(args)
        assert settings.enabled is True
        assert settings.virustotal_api_key == "abc123"

    def test_disabled_when_flag_not_passed(self, monkeypatch):
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        args = parse_args([])
        settings = threat_intel_settings_from_args(args)
        assert settings.enabled is False


class TestAlertSettingsFromArgs:
    def test_builds_alert_settings_from_parsed_args(self):
        args = parse_args([
            "--enable-alerts", "--webhook-url", "https://example.invalid/hook",
            "--alert-min-severity", "critical",
        ])
        settings = alert_settings_from_args(args)
        assert settings.enabled is True
        assert settings.webhook_url == "https://example.invalid/hook"
        assert settings.min_severity == "critical"

    def test_disabled_when_flag_not_passed(self, monkeypatch):
        monkeypatch.delenv("DNS_ANALYZER_WEBHOOK_URL", raising=False)
        settings = alert_settings_from_args(parse_args([]))
        assert settings.enabled is False
