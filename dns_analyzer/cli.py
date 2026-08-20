"""Command-line entry point."""

import argparse
import logging
import os
from dataclasses import asdict
from pathlib import Path
from typing import List, Optional

from dns_analyzer.alerting import (
    DEFAULT_ALERT_MIN_SEVERITY,
    SEVERITY_LEVELS,
    AlertSettings,
    WebhookAlerter,
)
from dns_analyzer.analysis import analyze_pcap
from dns_analyzer.capture import capture_dns_packets
from dns_analyzer.config import load_config
from dns_analyzer.detection import (
    DEFAULT_BURST_UNIQUE_SUBDOMAIN_THRESHOLD,
    DEFAULT_BURST_WINDOW_SECONDS,
    DEFAULT_ENTROPY_THRESHOLD,
    DEFAULT_MIN_BASELINE_SAMPLES,
    DEFAULT_MIN_NXDOMAIN_SAMPLES,
    DEFAULT_NXDOMAIN_RATIO_THRESHOLD,
    DEFAULT_Z_SCORE_THRESHOLD,
    DetectionSettings,
)
from dns_analyzer.live import capture_and_detect_live
from dns_analyzer.threat_intel import (
    DEFAULT_CACHE_TTL_SECONDS,
    ThreatIntelChecker,
    ThreatIntelSettings,
)

logger = logging.getLogger(__name__)


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
        help="Duration to capture DNS traffic, in seconds. 0 or negative captures "
             "indefinitely until interrupted with Ctrl+C (default: 60)",
    )
    parser.add_argument(
        "--live", action="store_true", default=config.get("live", False),
        help=(
            "Run detection (and alerting, if enabled) inline as each packet arrives, "
            "instead of only after the capture window ends. Uses incremental/streaming "
            "versions of the same detection algorithms - see DOCUMENTATION.md for how "
            "this differs numerically from batch mode's entropy z-scores."
        ),
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
        "--z-score-threshold", type=float,
        default=config.get("z_score_threshold", DEFAULT_Z_SCORE_THRESHOLD),
        help=(
            "Per-host entropy z-score above which a query is flagged as anomalous "
            f"(default: {DEFAULT_Z_SCORE_THRESHOLD})"
        ),
    )
    parser.add_argument(
        "--min-baseline-samples", type=int,
        default=config.get("min_baseline_samples", DEFAULT_MIN_BASELINE_SAMPLES),
        help=(
            "Minimum queries from a host before it gets its own entropy baseline "
            f"(default: {DEFAULT_MIN_BASELINE_SAMPLES})"
        ),
    )
    parser.add_argument(
        "--burst-window-seconds", type=int,
        default=config.get("burst_window_seconds", DEFAULT_BURST_WINDOW_SECONDS),
        help=(
            "Time window for subdomain-burst (DNS tunneling) detection, in seconds "
            f"(default: {DEFAULT_BURST_WINDOW_SECONDS})"
        ),
    )
    parser.add_argument(
        "--burst-unique-subdomain-threshold", type=int,
        default=config.get("burst_unique_subdomain_threshold", DEFAULT_BURST_UNIQUE_SUBDOMAIN_THRESHOLD),
        help=(
            "Unique subdomains under one parent domain within the burst window to flag as "
            f"possible tunneling (default: {DEFAULT_BURST_UNIQUE_SUBDOMAIN_THRESHOLD})"
        ),
    )
    parser.add_argument(
        "--nxdomain-ratio-threshold", type=float,
        default=config.get("nxdomain_ratio_threshold", DEFAULT_NXDOMAIN_RATIO_THRESHOLD),
        help=(
            "Fraction of NXDOMAIN responses to a client above which it's flagged as a "
            f"possible DGA client (default: {DEFAULT_NXDOMAIN_RATIO_THRESHOLD})"
        ),
    )
    parser.add_argument(
        "--min-nxdomain-samples", type=int,
        default=config.get("min_nxdomain_samples", DEFAULT_MIN_NXDOMAIN_SAMPLES),
        help=(
            "Minimum responses to a client before its NXDOMAIN ratio is evaluated "
            f"(default: {DEFAULT_MIN_NXDOMAIN_SAMPLES})"
        ),
    )
    parser.add_argument(
        "--enable-threat-intel", action="store_true",
        default=config.get("enable_threat_intel", False),
        help=(
            "Check observed domains against threat-intel feeds (OpenPhish always; URLhaus "
            "and VirusTotal if their API keys are set). Off by default: this sends every "
            "observed domain to third-party services, which is a privacy/opsec consideration."
        ),
    )
    parser.add_argument(
        "--urlhaus-api-key",
        default=config.get("urlhaus_api_key") or os.environ.get("URLHAUS_API_KEY"),
        help=(
            "URLhaus (abuse.ch) Auth-Key to enable URLhaus domain lookups (only used if "
            "--enable-threat-intel is set; free account at https://auth.abuse.ch/). Falls "
            "back to the URLHAUS_API_KEY environment variable - preferred over a config "
            "file, to avoid committing keys."
        ),
    )
    parser.add_argument(
        "--virustotal-api-key",
        default=config.get("virustotal_api_key") or os.environ.get("VIRUSTOTAL_API_KEY"),
        help=(
            "VirusTotal API key to enable VirusTotal domain lookups (only used if "
            "--enable-threat-intel is set). Falls back to the VIRUSTOTAL_API_KEY "
            "environment variable - preferred over a config file, to avoid committing keys."
        ),
    )
    parser.add_argument(
        "--threat-intel-cache-ttl-seconds", type=float,
        default=config.get("threat_intel_cache_ttl_seconds", DEFAULT_CACHE_TTL_SECONDS),
        help=(
            "How long to cache a threat-intel verdict for a domain before re-checking it "
            f"(default: {DEFAULT_CACHE_TTL_SECONDS})"
        ),
    )
    parser.add_argument(
        "--enable-alerts", action="store_true",
        default=config.get("enable_alerts", False),
        help=(
            "Send a webhook alert for records at or above --alert-min-severity. Off by "
            "default. Most useful with --live, where alerts fire as anomalies are "
            "observed rather than only after the capture window ends."
        ),
    )
    parser.add_argument(
        "--webhook-url",
        default=config.get("webhook_url") or os.environ.get("DNS_ANALYZER_WEBHOOK_URL"),
        help=(
            "Slack- or Discord-compatible incoming webhook URL to send alerts to (only "
            "used if --enable-alerts is set). Falls back to the DNS_ANALYZER_WEBHOOK_URL "
            "environment variable - preferred over a config file, to avoid committing it."
        ),
    )
    parser.add_argument(
        "--alert-min-severity", choices=SEVERITY_LEVELS,
        default=config.get("alert_min_severity", DEFAULT_ALERT_MIN_SEVERITY),
        help=f"Minimum severity to alert on: {', '.join(SEVERITY_LEVELS)} (default: {DEFAULT_ALERT_MIN_SEVERITY})",
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


def settings_from_args(args: argparse.Namespace) -> DetectionSettings:
    return DetectionSettings(
        entropy_threshold=args.entropy_threshold,
        z_score_threshold=args.z_score_threshold,
        min_baseline_samples=args.min_baseline_samples,
        burst_window_seconds=args.burst_window_seconds,
        burst_unique_subdomain_threshold=args.burst_unique_subdomain_threshold,
        nxdomain_ratio_threshold=args.nxdomain_ratio_threshold,
        min_nxdomain_samples=args.min_nxdomain_samples,
    )


def threat_intel_settings_from_args(args: argparse.Namespace) -> ThreatIntelSettings:
    return ThreatIntelSettings(
        enabled=args.enable_threat_intel,
        urlhaus_api_key=args.urlhaus_api_key,
        virustotal_api_key=args.virustotal_api_key,
        cache_ttl_seconds=args.threat_intel_cache_ttl_seconds,
    )


def alert_settings_from_args(args: argparse.Namespace) -> AlertSettings:
    return AlertSettings(
        enabled=args.enable_alerts,
        webhook_url=args.webhook_url,
        min_severity=args.alert_min_severity,
    )


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(asctime)s [%(levelname)s] %(message)s")
    logger.info("DNS Analyzer - developed by CipherxHub")
    logger.debug("Detection settings: %s", asdict(settings_from_args(args)))

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    pcap_file = str(output_dir / args.pcap_file)
    json_file = str(output_dir / args.json_file)
    report_file = str(output_dir / args.report_file)

    threat_intel_settings = threat_intel_settings_from_args(args)
    threat_intel_checker = ThreatIntelChecker(threat_intel_settings) if threat_intel_settings.enabled else None
    if threat_intel_settings.enabled:
        providers = ["OpenPhish"]
        if threat_intel_settings.urlhaus_api_key:
            providers.append("URLhaus")
        if threat_intel_settings.virustotal_api_key:
            providers.append("VirusTotal")
        logger.info("Threat-intel checks enabled (%s).", " + ".join(providers))

    alert_settings = alert_settings_from_args(args)
    alerter = None
    if alert_settings.enabled:
        if alert_settings.webhook_url:
            alerter = WebhookAlerter(alert_settings)
            logger.info("Webhook alerting enabled (min severity: %s).", alert_settings.min_severity)
        else:
            logger.warning("--enable-alerts was set but no webhook URL was configured; alerting is disabled.")

    settings = settings_from_args(args)

    if args.live:
        try:
            records = capture_and_detect_live(
                args.duration, args.iface, pcap_file, json_file, report_file,
                settings, threat_intel_checker, alerter,
            )
        except (PermissionError, OSError):
            return 1
        if not records:
            logger.warning("No DNS traffic captured; nothing to report.")
        return 0

    try:
        packets = capture_dns_packets(args.duration, args.iface, pcap_file)
    except (PermissionError, OSError):
        return 1

    if not packets:
        logger.warning("No DNS traffic captured; skipping analysis.")
        return 0

    try:
        analyze_pcap(pcap_file, json_file, report_file, settings, threat_intel_checker, alerter)
    except (FileNotFoundError, ValueError) as exc:
        logger.error(str(exc))
        return 1

    return 0
