"""Syslog/CEF forwarding for SIEM ingestion (Phase 5).

Formats detection records as CEF (Common Event Format) - the de facto
standard most SIEMs (Splunk, QRadar, ArcSight, and general syslog-CEF
listeners) parse out of the box - and forwards them over syslog
(UDP or TCP).

Like alerting.py: the actual network send goes through an injectable
"sender" function, so this is fully testable without a real syslog
listener, and a forwarding failure never breaks capture/detection -
forwarding is a side effect layered on top of the pipeline.
"""

import logging
import logging.handlers
import socket
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from dnspector._version import __version__
from dnspector.alerting import SEVERITY_LEVELS, classify_severity

logger = logging.getLogger(__name__)

CEF_VENDOR = "DNSpector"
CEF_PRODUCT = "dnspector"
CEF_SIGNATURE_ID = "dns-anomaly"
# Rough CEF severity buckets (0-10 scale): Low/Medium/High/Very-High.
SEVERITY_TO_CEF = {"info": 1, "medium": 4, "high": 7, "critical": 10}

DEFAULT_SYSLOG_PORT = 514
DEFAULT_SYSLOG_PROTOCOL = "udp"
# Unlike alerting's default of "high" (only page a human for something
# serious), SIEM forwarding defaults to "info" (forward everything) -
# the point of sending data to a SIEM is usually full-fidelity event
# history for later search/correlation, not just the loud stuff.
DEFAULT_SYSLOG_MIN_SEVERITY = "info"


@dataclass
class SyslogSettings:
    enabled: bool = False
    host: Optional[str] = None
    port: int = DEFAULT_SYSLOG_PORT
    protocol: str = DEFAULT_SYSLOG_PROTOCOL  # "udp" or "tcp"
    min_severity: str = DEFAULT_SYSLOG_MIN_SEVERITY


def _cef_escape_header(value: Any) -> str:
    text = str(value).replace("\\", "\\\\").replace("|", "\\|")
    return text.replace("\n", " ").replace("\r", " ")


def _cef_escape_extension(value: Any) -> str:
    text = str(value).replace("\\", "\\\\").replace("=", "\\=")
    return text.replace("\n", " ").replace("\r", " ")


def format_cef(record: Dict[str, Any], severity: str) -> str:
    """Format a record as a single CEF syslog message line."""
    name = _cef_escape_header(record.get("remark") or "DNS event")[:200]
    cef_severity = SEVERITY_TO_CEF.get(severity, 1)

    header = "|".join([
        "CEF:0", CEF_VENDOR, CEF_PRODUCT, __version__, CEF_SIGNATURE_ID, name, str(cef_severity),
    ])

    extensions = {
        "src": record.get("source_ip"),
        "dst": record.get("destination_ip"),
        "request": record.get("query"),
        "msg": record.get("remark"),
        "cs1Label": "registrableDomain",
        "cs1": record.get("registrable_domain"),
        "cn1Label": "entropy",
        "cn1": f"{record['entropy']:.4f}" if record.get("entropy") is not None else None,
        "cs2Label": "severity",
        "cs2": severity,
    }
    extension_str = " ".join(
        f"{key}={_cef_escape_extension(value)}"
        for key, value in extensions.items()
        if value not in (None, "")
    )
    return f"{header}|{extension_str}"


class SyslogCefForwarder:
    """Forwards records at or above settings.min_severity as CEF syslog
    messages. Constructing this with settings.host unset and no injected
    sender is a no-op (never opens a real socket) - callers should check
    settings.host themselves and warn the user if they expect forwarding
    but didn't configure a host (see cli.py).
    """

    def __init__(
        self,
        settings: SyslogSettings,
        sender: Optional[Callable[[str], None]] = None,
    ):
        self.settings = settings
        self._handler: Optional[logging.handlers.SysLogHandler] = None

        if sender is not None:
            self._sender: Optional[Callable[[str], None]] = sender
        elif settings.host:
            self._handler = logging.handlers.SysLogHandler(
                address=(settings.host, settings.port),
                socktype=socket.SOCK_DGRAM if settings.protocol == "udp" else socket.SOCK_STREAM,
            )
            self._sender = self._emit
        else:
            self._sender = None

    def _emit(self, message: str) -> None:
        log_record = logging.LogRecord(
            name="dnspector.cef", level=logging.INFO, pathname="", lineno=0,
            msg=message, args=None, exc_info=None,
        )
        self._handler.emit(log_record)

    def maybe_forward(self, record: Dict[str, Any]) -> Optional[str]:
        """Forward the record if its severity meets the configured
        minimum. Returns the classified severity if the threshold was
        met (regardless of whether the send itself succeeded), else None.
        """
        severity = record.get("severity") or classify_severity(record)
        if SEVERITY_LEVELS.index(severity) < SEVERITY_LEVELS.index(self.settings.min_severity):
            return None
        if not self.settings.enabled or self._sender is None:
            return None

        message = format_cef(record, severity)
        try:
            self._sender(message)
        except Exception as exc:
            logger.warning("Failed to forward syslog/CEF message: %s", exc)

        return severity

    def close(self) -> None:
        if self._handler is not None:
            self._handler.close()
