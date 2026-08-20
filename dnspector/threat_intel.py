"""Threat-intelligence feed integration.

Checks a domain's *registrable domain* against known-bad-domain feeds -
OpenPhish is free and needs no API key; URLhaus and VirusTotal are both
free but require a (free) API key each. This turns a heuristic "looks
suspicious" verdict into a confirmed "is on a real-world blocklist" one.

Note on URLhaus: as of 2025, abuse.ch requires an `Auth-Key` header on
every URLhaus API request (obtained via a free account at
https://auth.abuse.ch/) - this was discovered by testing the live API
while building this integration (it returns a plain `401 Unauthorized`
with no key, and `403 {"query_status": "unknown_auth_key"}` with an
invalid one). Earlier abuse.ch API docs describe URLhaus as keyless, so
this integration fails closed (skips URLhaus, falls through to the next
provider) rather than silently hammering the API with requests that
will only ever 401.

Design notes:

- Disabled by default (see DetectionSettings/cli.py). Threat-intel
  checks send every observed domain to third-party services, which is a
  genuine privacy/opsec consideration for a tool that's meant to be
  monitoring potentially sensitive network traffic - this should be an
  explicit opt-in (--enable-threat-intel), never silent default
  behavior.
- Every network call is wrapped so a feed outage, timeout, or API error
  degrades to "no verdict from that provider" (logged as a warning)
  rather than crashing the whole analysis run - threat intel is a bonus
  signal on top of the local heuristics, not a hard dependency.
- All HTTP calls go through small injectable "fetcher" functions so
  this whole module is testable with fake fetchers - no real network
  access, and no flaky/slow tests, needed.
"""

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, List, Optional, Set

from dnspector.dns_parsing import parse_domain

logger = logging.getLogger(__name__)

URLHAUS_HOST_API = "https://urlhaus-api.abuse.ch/v1/host/"
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
VIRUSTOTAL_DOMAIN_API = "https://www.virustotal.com/api/v3/domains"

DEFAULT_CACHE_TTL_SECONDS = 3600.0
DEFAULT_OPENPHISH_REFRESH_SECONDS = 3600.0
DEFAULT_REQUEST_TIMEOUT_SECONDS = 5.0
DEFAULT_VIRUSTOTAL_MIN_INTERVAL_SECONDS = 15.0  # ~4 requests/minute, VT's free-tier limit
DEFAULT_VIRUSTOTAL_MAX_LOOKUPS_PER_RUN = 20


@dataclass
class ThreatIntelSettings:
    """Tunable behavior for threat-intel feed checks. Not exposed as CLI
    flags beyond `enabled` and the two API keys - the rest have sensible
    fixed defaults to keep the CLI surface manageable; set them directly
    if you're constructing DetectionSettings/checks yourself.
    """

    enabled: bool = False
    urlhaus_enabled: bool = True
    openphish_enabled: bool = True
    urlhaus_api_key: Optional[str] = None  # required - see module docstring
    virustotal_api_key: Optional[str] = None
    cache_ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS
    openphish_refresh_seconds: float = DEFAULT_OPENPHISH_REFRESH_SECONDS
    request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS
    virustotal_min_interval_seconds: float = DEFAULT_VIRUSTOTAL_MIN_INTERVAL_SECONDS
    virustotal_max_lookups_per_run: int = DEFAULT_VIRUSTOTAL_MAX_LOOKUPS_PER_RUN


@dataclass
class ThreatIntelVerdict:
    is_malicious: bool
    source: Optional[str]  # which provider produced this verdict, e.g. "urlhaus"; None if clean
    detail: str
    checked_at: float


def _fetch_urlhaus(domain: str, api_key: str, timeout: float) -> Dict[str, Any]:
    """Query the URLhaus host API for a single domain. Raises on network/HTTP errors.

    Requires an Auth-Key (free account at https://auth.abuse.ch/) - see
    the module docstring for how this was discovered.
    """
    data = urllib.parse.urlencode({"host": domain}).encode()
    req = urllib.request.Request(
        URLHAUS_HOST_API, data=data, headers={"User-Agent": "dnspector", "Auth-Key": api_key}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _fetch_openphish_feed(timeout: float) -> str:
    """Download the free OpenPhish active-phishing-URL feed as plain text."""
    req = urllib.request.Request(OPENPHISH_FEED_URL, headers={"User-Agent": "dnspector"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode()


def _fetch_virustotal(domain: str, api_key: str, timeout: float) -> Dict[str, Any]:
    """Query the VirusTotal v3 domain report API. Raises on network/HTTP errors."""
    req = urllib.request.Request(
        f"{VIRUSTOTAL_DOMAIN_API}/{domain}",
        headers={"x-apikey": api_key, "User-Agent": "dnspector"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


class IOCCache:
    """A small in-memory TTL cache of threat-intel verdicts, keyed by
    registrable domain. Caches *both* malicious and clean verdicts -
    most observed domains are clean, so caching only positives would
    miss most of the benefit (the same clean domain showing up
    repeatedly in a capture would otherwise be re-queried every time).
    """

    def __init__(self, ttl_seconds: float, now_fn: Callable[[], float] = time.time):
        self._ttl = ttl_seconds
        self._now_fn = now_fn
        self._store: Dict[str, ThreatIntelVerdict] = {}

    def get(self, domain: str) -> Optional[ThreatIntelVerdict]:
        entry = self._store.get(domain)
        if entry is None:
            return None
        if self._now_fn() - entry.checked_at > self._ttl:
            del self._store[domain]
            return None
        return entry

    def set(self, domain: str, verdict: ThreatIntelVerdict) -> None:
        self._store[domain] = verdict


class OpenPhishFeed:
    """Downloads and caches the OpenPhish active-phishing feed, refreshing
    it at most once per `refresh_seconds`. The free OpenPhish tier only
    offers a bulk feed (no single-domain lookup API), so membership is
    checked against a locally parsed set of registrable domains.
    """

    def __init__(
        self,
        fetch_fn: Callable[[float], str] = _fetch_openphish_feed,
        refresh_seconds: float = DEFAULT_OPENPHISH_REFRESH_SECONDS,
        request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
        now_fn: Callable[[], float] = time.time,
    ):
        self._fetch_fn = fetch_fn
        self._refresh_seconds = refresh_seconds
        self._request_timeout_seconds = request_timeout_seconds
        self._now_fn = now_fn
        self._domains: Set[str] = set()
        self._fetched_at: float = 0.0

    def _ensure_fresh(self) -> None:
        if self._domains and self._now_fn() - self._fetched_at < self._refresh_seconds:
            return
        text = self._fetch_fn(self._request_timeout_seconds)
        domains: Set[str] = set()
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            host = urllib.parse.urlparse(line).hostname
            if not host:
                continue
            registrable = parse_domain(host).registrable_domain
            domains.add(registrable or host)
        self._domains = domains
        self._fetched_at = self._now_fn()

    def contains(self, registrable_domain: str) -> bool:
        self._ensure_fresh()
        return registrable_domain in self._domains


class ThreatIntelChecker:
    """Checks a registrable domain against enabled threat-intel providers,
    in order (URLhaus, then OpenPhish, then VirusTotal), stopping at the
    first confirmed-malicious verdict. Results are cached (both
    malicious and clean) for `settings.cache_ttl_seconds`.
    """

    def __init__(
        self,
        settings: ThreatIntelSettings,
        urlhaus_fetcher: Callable[[str, str, float], Dict[str, Any]] = _fetch_urlhaus,
        openphish_feed: Optional[OpenPhishFeed] = None,
        virustotal_fetcher: Callable[[str, str, float], Dict[str, Any]] = _fetch_virustotal,
        now_fn: Callable[[], float] = time.time,
    ):
        self.settings = settings
        self._now_fn = now_fn
        self._cache = IOCCache(settings.cache_ttl_seconds, now_fn=now_fn)
        self._urlhaus_fetcher = urlhaus_fetcher
        self._openphish_feed = openphish_feed or OpenPhishFeed(
            refresh_seconds=settings.openphish_refresh_seconds,
            request_timeout_seconds=settings.request_timeout_seconds,
            now_fn=now_fn,
        )
        self._virustotal_fetcher = virustotal_fetcher
        self._last_vt_call = 0.0
        self._vt_lookup_count = 0

    def check(self, registrable_domain: str) -> ThreatIntelVerdict:
        now = self._now_fn()
        if not registrable_domain:
            return ThreatIntelVerdict(False, None, "no registrable domain to check", now)

        cached = self._cache.get(registrable_domain)
        if cached is not None:
            return cached

        verdict = self._check_uncached(registrable_domain, now)
        self._cache.set(registrable_domain, verdict)
        return verdict

    def _check_uncached(self, domain: str, now: float) -> ThreatIntelVerdict:
        if self.settings.urlhaus_enabled and self.settings.urlhaus_api_key:
            verdict = self._check_urlhaus(domain, now)
            if verdict is not None:
                return verdict
        if self.settings.openphish_enabled:
            verdict = self._check_openphish(domain, now)
            if verdict is not None:
                return verdict
        if self.settings.virustotal_api_key:
            verdict = self._check_virustotal(domain, now)
            if verdict is not None:
                return verdict
        return ThreatIntelVerdict(False, None, "no match in any enabled feed", now)

    def _check_urlhaus(self, domain: str, now: float) -> Optional[ThreatIntelVerdict]:
        try:
            data = self._urlhaus_fetcher(
                domain, self.settings.urlhaus_api_key, self.settings.request_timeout_seconds
            )
        except Exception as exc:
            logger.warning("URLhaus lookup failed for %s: %s", domain, exc)
            return None
        if data.get("query_status") == "ok":
            url_count = data.get("url_count", "unknown")
            return ThreatIntelVerdict(True, "urlhaus", f"{url_count} malicious URL(s) on record", now)
        return None

    def _check_openphish(self, domain: str, now: float) -> Optional[ThreatIntelVerdict]:
        try:
            if self._openphish_feed.contains(domain):
                return ThreatIntelVerdict(True, "openphish", "listed in the OpenPhish active feed", now)
        except Exception as exc:
            logger.warning("OpenPhish check failed for %s: %s", domain, exc)
        return None

    def _check_virustotal(self, domain: str, now: float) -> Optional[ThreatIntelVerdict]:
        if self._vt_lookup_count >= self.settings.virustotal_max_lookups_per_run:
            logger.debug("Skipping VirusTotal lookup for %s (per-run lookup budget exhausted)", domain)
            return None
        if now - self._last_vt_call < self.settings.virustotal_min_interval_seconds:
            logger.debug("Skipping VirusTotal lookup for %s (rate limit)", domain)
            return None

        self._last_vt_call = now
        self._vt_lookup_count += 1
        try:
            data = self._virustotal_fetcher(
                domain, self.settings.virustotal_api_key, self.settings.request_timeout_seconds
            )
        except Exception as exc:
            logger.warning("VirusTotal lookup failed for %s: %s", domain, exc)
            return None

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        if malicious > 0 or suspicious > 0:
            detail = f"{malicious} malicious / {suspicious} suspicious vendor flags"
            return ThreatIntelVerdict(True, "virustotal", detail, now)
        return None


def annotate_threat_intel(record: Dict[str, Any], checker: ThreatIntelChecker) -> Dict[str, Any]:
    """Annotate a single record with a threat-intel verdict for its
    registrable domain. checker.check() caches internally, so repeated
    domains (across many calls, batch or live) only trigger one real
    provider lookup. No-op if the record has no registrable domain.
    """
    domain = record.get("registrable_domain")
    if not domain:
        return record

    verdict = checker.check(domain)
    record["threat_intel"] = asdict(verdict)
    if verdict.is_malicious:
        record["remark"] += f" | domain matches {verdict.source} threat intel: {verdict.detail}"

    return record


def apply_threat_intel(
    records: List[Dict[str, Any]],
    checker: ThreatIntelChecker,
) -> List[Dict[str, Any]]:
    """Batch version of annotate_threat_intel() - annotates every record
    in a list. Used by the batch analysis pipeline; live capture calls
    annotate_threat_intel() directly, one record at a time, as it arrives.
    """
    for record in records:
        annotate_threat_intel(record, checker)
    return records
