from dnspector.threat_intel import (
    IOCCache,
    OpenPhishFeed,
    ThreatIntelChecker,
    ThreatIntelSettings,
    ThreatIntelVerdict,
    apply_threat_intel,
)


class FakeClock:
    """An injectable now_fn that only advances when told to - lets tests
    exercise TTL/rate-limit logic deterministically, with no real sleeping.
    """

    def __init__(self, start: float = 1000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class TestIOCCache:
    def test_miss_returns_none(self):
        cache = IOCCache(ttl_seconds=60)
        assert cache.get("evil.com") is None

    def test_set_then_get_returns_the_verdict(self):
        clock = FakeClock()
        cache = IOCCache(ttl_seconds=60, now_fn=clock)
        verdict = ThreatIntelVerdict(True, "urlhaus", "matched", clock())
        cache.set("evil.com", verdict)
        assert cache.get("evil.com") is verdict

    def test_entry_expires_after_ttl(self):
        clock = FakeClock()
        cache = IOCCache(ttl_seconds=60, now_fn=clock)
        cache.set("evil.com", ThreatIntelVerdict(False, None, "clean", clock()))
        clock.advance(61)
        assert cache.get("evil.com") is None

    def test_entry_survives_within_ttl(self):
        clock = FakeClock()
        cache = IOCCache(ttl_seconds=60, now_fn=clock)
        cache.set("evil.com", ThreatIntelVerdict(False, None, "clean", clock()))
        clock.advance(59)
        assert cache.get("evil.com") is not None


class TestOpenPhishFeed:
    def test_parses_registrable_domains_from_feed_urls(self):
        text = "https://a1b2.tunnel.evil.com/login\nhttps://phish.example.net/paypal\n"
        feed = OpenPhishFeed(fetch_fn=lambda timeout: text)
        assert feed.contains("evil.com")
        assert feed.contains("example.net")
        assert not feed.contains("google.com")

    def test_does_not_refetch_within_refresh_window(self):
        clock = FakeClock()
        calls = []

        def fetch(timeout):
            calls.append(1)
            return "https://evil.com/x\n"

        feed = OpenPhishFeed(fetch_fn=fetch, refresh_seconds=3600, now_fn=clock)
        feed.contains("evil.com")
        clock.advance(100)
        feed.contains("evil.com")
        assert len(calls) == 1

    def test_refetches_after_refresh_window_elapses(self):
        clock = FakeClock()
        calls = []

        def fetch(timeout):
            calls.append(1)
            return "https://evil.com/x\n"

        feed = OpenPhishFeed(fetch_fn=fetch, refresh_seconds=3600, now_fn=clock)
        feed.contains("evil.com")
        clock.advance(3601)
        feed.contains("evil.com")
        assert len(calls) == 2


class TestThreatIntelChecker:
    def test_urlhaus_positive_match(self):
        checker = ThreatIntelChecker(
            ThreatIntelSettings(urlhaus_api_key="test-key"),
            urlhaus_fetcher=lambda domain, api_key, timeout: {"query_status": "ok", "url_count": "3"},
        )
        verdict = checker.check("evil.com")
        assert verdict.is_malicious
        assert verdict.source == "urlhaus"

    def test_urlhaus_skipped_without_api_key(self):
        # URLhaus (abuse.ch) requires a free Auth-Key as of 2025 - see module
        # docstring. Without one configured, it must not be queried at all.
        calls = []

        def urlhaus_fetcher(domain, api_key, timeout):
            calls.append(domain)
            return {"query_status": "ok", "url_count": "3"}

        checker = ThreatIntelChecker(
            ThreatIntelSettings(urlhaus_api_key=None),
            urlhaus_fetcher=urlhaus_fetcher,
            openphish_feed=OpenPhishFeed(fetch_fn=lambda timeout: ""),
        )
        verdict = checker.check("evil.com")
        assert calls == []
        assert not verdict.is_malicious

    def test_falls_through_to_openphish_when_urlhaus_clean(self):
        checker = ThreatIntelChecker(
            ThreatIntelSettings(urlhaus_api_key="test-key"),
            urlhaus_fetcher=lambda domain, api_key, timeout: {"query_status": "no_results"},
            openphish_feed=OpenPhishFeed(fetch_fn=lambda timeout: "https://evil.com/x\n"),
        )
        verdict = checker.check("evil.com")
        assert verdict.is_malicious
        assert verdict.source == "openphish"

    def test_clean_when_no_provider_matches(self):
        checker = ThreatIntelChecker(
            ThreatIntelSettings(urlhaus_api_key="test-key"),
            urlhaus_fetcher=lambda domain, api_key, timeout: {"query_status": "no_results"},
            openphish_feed=OpenPhishFeed(fetch_fn=lambda timeout: "https://other.com/x\n"),
        )
        verdict = checker.check("clean-site.com")
        assert not verdict.is_malicious
        assert verdict.source is None

    def test_provider_error_is_swallowed_and_falls_through(self):
        def failing_urlhaus(domain, api_key, timeout):
            raise TimeoutError("network unreachable")

        checker = ThreatIntelChecker(
            ThreatIntelSettings(urlhaus_api_key="test-key"),
            urlhaus_fetcher=failing_urlhaus,
            openphish_feed=OpenPhishFeed(fetch_fn=lambda timeout: "https://evil.com/x\n"),
        )
        verdict = checker.check("evil.com")
        assert verdict.is_malicious
        assert verdict.source == "openphish"

    def test_repeated_check_uses_cache_not_fetcher(self):
        calls = []

        def urlhaus_fetcher(domain, api_key, timeout):
            calls.append(domain)
            return {"query_status": "no_results"}

        checker = ThreatIntelChecker(
            ThreatIntelSettings(urlhaus_api_key="test-key"),
            urlhaus_fetcher=urlhaus_fetcher,
            openphish_feed=OpenPhishFeed(fetch_fn=lambda timeout: ""),
        )
        checker.check("example.com")
        checker.check("example.com")
        assert len(calls) == 1

    def test_empty_domain_is_clean_and_uncached_lookup(self):
        verdict = ThreatIntelChecker(ThreatIntelSettings()).check("")
        assert not verdict.is_malicious

    def test_virustotal_only_checked_when_api_key_present(self):
        calls = []

        def vt_fetcher(domain, api_key, timeout):
            calls.append(domain)
            return {"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 0}}}}

        settings = ThreatIntelSettings(urlhaus_enabled=False, openphish_enabled=False, virustotal_api_key=None)
        checker = ThreatIntelChecker(settings, virustotal_fetcher=vt_fetcher)
        verdict = checker.check("evil.com")
        assert not verdict.is_malicious
        assert calls == []

    def test_virustotal_positive_match_when_api_key_present(self):
        def vt_fetcher(domain, api_key, timeout):
            return {"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 1}}}}

        settings = ThreatIntelSettings(
            urlhaus_enabled=False, openphish_enabled=False, virustotal_api_key="fake-key"
        )
        checker = ThreatIntelChecker(settings, virustotal_fetcher=vt_fetcher)
        verdict = checker.check("evil.com")
        assert verdict.is_malicious
        assert verdict.source == "virustotal"
        assert "5 malicious" in verdict.detail

    def test_virustotal_rate_limit_skips_second_call_within_interval(self):
        clock = FakeClock()
        calls = []

        def vt_fetcher(domain, api_key, timeout):
            calls.append(domain)
            return {"data": {"attributes": {"last_analysis_stats": {}}}}

        settings = ThreatIntelSettings(
            urlhaus_enabled=False,
            openphish_enabled=False,
            virustotal_api_key="fake-key",
            virustotal_min_interval_seconds=15,
        )
        checker = ThreatIntelChecker(settings, virustotal_fetcher=vt_fetcher, now_fn=clock)
        checker.check("first.com")
        clock.advance(1)  # well within the 15s minimum interval
        checker.check("second.com")
        assert calls == ["first.com"]

    def test_virustotal_lookup_budget_enforced(self):
        clock = FakeClock()
        calls = []

        def vt_fetcher(domain, api_key, timeout):
            calls.append(domain)
            return {"data": {"attributes": {"last_analysis_stats": {}}}}

        settings = ThreatIntelSettings(
            urlhaus_enabled=False,
            openphish_enabled=False,
            virustotal_api_key="fake-key",
            virustotal_min_interval_seconds=0,
            virustotal_max_lookups_per_run=2,
        )
        checker = ThreatIntelChecker(settings, virustotal_fetcher=vt_fetcher, now_fn=clock)
        for i in range(5):
            checker.check(f"site{i}.com")
            clock.advance(1)
        assert len(calls) == 2


class TestApplyThreatIntel:
    def test_attaches_verdict_and_appends_note_when_malicious(self):
        records = [
            {"registrable_domain": "evil.com", "remark": "Normal query", "threat_intel": None},
        ]
        checker = ThreatIntelChecker(
            ThreatIntelSettings(urlhaus_api_key="test-key"),
            urlhaus_fetcher=lambda domain, api_key, timeout: {"query_status": "ok", "url_count": "2"},
        )
        result = apply_threat_intel(records, checker)
        assert result[0]["threat_intel"]["is_malicious"] is True
        assert "urlhaus" in result[0]["remark"]

    def test_attaches_clean_verdict_without_altering_remark(self):
        records = [
            {"registrable_domain": "clean.com", "remark": "Normal query", "threat_intel": None},
        ]
        checker = ThreatIntelChecker(
            ThreatIntelSettings(urlhaus_api_key="test-key"),
            urlhaus_fetcher=lambda domain, api_key, timeout: {"query_status": "no_results"},
            openphish_feed=OpenPhishFeed(fetch_fn=lambda timeout: ""),
        )
        result = apply_threat_intel(records, checker)
        assert result[0]["threat_intel"]["is_malicious"] is False
        assert result[0]["remark"] == "Normal query"

    def test_record_without_registrable_domain_is_skipped(self):
        records = [{"registrable_domain": "", "remark": "Normal query", "threat_intel": None}]
        checker = ThreatIntelChecker(ThreatIntelSettings())
        result = apply_threat_intel(records, checker)
        assert result[0]["threat_intel"] is None
        assert result[0]["remark"] == "Normal query"
