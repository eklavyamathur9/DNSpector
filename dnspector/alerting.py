"""Webhook alerting for high-severity detection results.

Fires a webhook when a record's severity meets a configured threshold -
usable in both live and batch mode, but most useful in live mode where
alerts go out as the anomaly is observed, not after the whole capture
window ends.

Like threat_intel.py: every network call goes through an injectable
"sender" function (real network access by default) so this is fully
testable without a real webhook endpoint, and a webhook outage never
breaks capture/detection - alerting is a side effect on top of the
pipeline, never something the pipeline depends on succeeding.
"""

import json
import logging
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)

# Ordered low -> high, so a configured minimum can be compared numerically.
SEVERITY_LEVELS = ["info", "medium", "high", "critical"]
DEFAULT_ALERT_MIN_SEVERITY = "high"
DEFAULT_REQUEST_TIMEOUT_SECONDS = 5.0


def classify_severity(record: Dict[str, Any]) -> str:
    """Classify a record into an alerting severity level.

    Reuses the already-computed `remark` and `threat_intel` fields as the
    single source of truth for "what's wrong with this record" - rather
    than re-deriving thresholds here (which risks drifting out of sync
    with detection.generate_remark()'s own logic).
    """
    threat_intel = record.get("threat_intel")
    if threat_intel and threat_intel.get("is_malicious"):
        return "critical"

    remark = record.get("remark", "").lower()
    if "dga" in remark or "tunneling" in remark:
        return "high"
    if "nxdomain ratio" in remark:
        return "high"
    if "refused" in remark or "misconfiguration" in remark or "attack" in remark:
        return "medium"
    return "info"


@dataclass
class AlertSettings:
    enabled: bool = False
    webhook_url: Optional[str] = None
    min_severity: str = DEFAULT_ALERT_MIN_SEVERITY
    request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS


def format_alert_message(record: Dict[str, Any], severity: str) -> str:
    return (
        f"[{severity.upper()}] DNS anomaly: {record.get('query', '?')} "
        f"(source {record.get('source_ip', '?')} -> {record.get('destination_ip', '?')})\n"
        f"{record.get('remark', '')}"
    )


def _send_webhook(url: str, payload: Dict[str, Any], timeout: float) -> None:
    """POST a JSON payload to a webhook URL. Raises on network/HTTP errors.

    Payload includes both "text" (Slack incoming-webhook format) and
    "content" (Discord webhook format) keys with the same message, so one
    payload works for either without a separate "webhook style" setting -
    both platforms ignore keys they don't recognize.
    """
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json", "User-Agent": "dnspector"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        resp.read()


class WebhookAlerter:
    """Sends a webhook alert for records whose severity meets
    settings.min_severity. Safe to call on every record - below-threshold
    or disabled/unconfigured cases are simply no-ops.
    """

    def __init__(
        self,
        settings: AlertSettings,
        sender: Callable[[str, Dict[str, Any], float], None] = _send_webhook,
    ):
        self.settings = settings
        self._sender = sender

    def maybe_alert(self, record: Dict[str, Any]) -> Optional[str]:
        """Send an alert if the record's severity meets the configured
        minimum. Returns the classified severity if the threshold was met
        (regardless of whether the send itself succeeded), else None.
        """
        severity = classify_severity(record)
        if SEVERITY_LEVELS.index(severity) < SEVERITY_LEVELS.index(self.settings.min_severity):
            return None
        if not self.settings.enabled or not self.settings.webhook_url:
            return None

        message = format_alert_message(record, severity)
        payload = {"text": message, "content": message}
        try:
            self._sender(self.settings.webhook_url, payload, self.settings.request_timeout_seconds)
        except Exception as exc:
            logger.warning("Failed to send webhook alert: %s", exc)

        return severity
