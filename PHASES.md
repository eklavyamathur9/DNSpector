# Project Roadmap

This is the working roadmap for evolving the DNS Analyzer from a solid single-signal detector into a portfolio-grade DNS security tool. Background on *why* each item matters (the DNS/security theory) lives in [DOCUMENTATION.md](DOCUMENTATION.md) — this file is the ordered, checklist-driven execution plan.

**How to use this file:** phases are worked **one at a time**, in order, each as its own focused piece of work with its own commit(s). Check off sub-items as they land, and add a one-line note (date + what changed) under a phase once it's fully complete. Don't jump ahead to a later phase before the current one is done unless there's a good reason — note the reason if you do.

---

## Phase 0 — Housekeeping ✅ *done*

- [x] Fix `parse_dns_flags()` opcode/rcode `IndexError` crash on uncommon DNS values (`OPCODES`/`RCODES` dicts with fallback)
- [x] Guard `calculate_entropy()` against divide-by-zero on an empty domain
- [x] Correct RCODE names to standard DNS terminology (`FORMERR`, `SERVFAIL`, `NXDOMAIN`)
- [x] Add `pytest` suite (`tests/`) covering entropy, flag parsing, and remark generation — 19 cases
- [x] Add `.gitignore`, `requirements-dev.txt`
- [x] Write `DOCUMENTATION.md` (architecture walkthrough, DNS theory, limitations, roadmap source)

---

## Phase 1 — Engineering Foundations ✅ *done*

**Why:** the tool currently only runs interactively and prints to stdout, which blocks scripting, CI, and any kind of automation — this phase makes it a proper CLI tool without touching detection logic.

- [x] Replace `input()` with `argparse` (`--duration`, `--iface`, `--output-dir`, `--entropy-threshold`, `--pcap-file`, `--json-file`, `--report-file`, `--log-level`)
- [x] Replace `print()` with the `logging` module (`logging.basicConfig`, level controlled by `--log-level`)
- [x] Add a JSON config file (`--config`, see `config.example.json`) for thresholds, interface, output paths, filenames — CLI flags override config file values, which override built-in defaults
- [x] Add type hints throughout
- [x] Add error handling for realistic failure modes: capture `PermissionError`/`OSError` (elevated-privilege guidance logged, clean exit code), no packets captured (skips analysis with a warning instead of crashing), missing/corrupt pcap file (`FileNotFoundError`/`ValueError` with a clean message), packets missing an IP layer (skipped via `build_dns_record()` returning `None`, logged as a count instead of crashing)
- [x] Add GitHub Actions CI (`.github/workflows/ci.yml`): `ruff check` + `pytest` on every push/PR to `main`, plus a CI badge in the README
- [x] Split into modules (`capture.py`, `analysis.py`, `report.py`, `cli.py`) — **deferred** here as planned; landed in Phase 3 once threat-intel code made the single file (~630 lines) genuinely unwieldy.

*Landed 2026-08-20. Test suite grew from 19 to 31 cases (`build_dns_record`, `load_config`, `parse_args`). `generate_remark()` gained an `entropy_threshold` parameter (defaults to 3.5, same as before) so Phase 2's baselining can pass a computed value instead of a hardcoded one.*

---

## Phase 2 — Detection Quality Core ✅ *done*

**Why:** this is the highest-value phase — it's the difference between "a script with an entropy check" and "a tool that understands DNS threats." See DOCUMENTATION.md §2.4 for the gap this closes.

- [x] Replace the fixed entropy threshold (3.5) with per-host/per-domain statistical baselining (rolling mean/stddev, z-score deviation) — `compute_host_baselines()` + `entropy_z_score()`, additive to (not a replacement for) the fixed threshold; `--z-score-threshold`, `--min-baseline-samples`
- [x] Add query-frequency/burst analysis: unique subdomain-label count per parent domain per time window (tunneling signal independent of entropy) — `detect_subdomain_bursts()`; `--burst-window-seconds`, `--burst-unique-subdomain-threshold`
- [x] Track NXDOMAIN ratio per source host (classic DGA-infected-host indicator) — `compute_nxdomain_ratios()`, correctly keyed by the client (`destination_ip` on a RESPONSE packet); `--nxdomain-ratio-threshold`, `--min-nxdomain-samples`
- [x] Normalize domains against the public suffix / TLD before scoring entropy (score the attacker-controlled label, not the whole FQDN) — `parse_domain()` via `tldextract` (offline mode, bundled snapshot, no network calls)
- [ ] (Stretch) small DGA classifier (n-gram/logistic regression) trained on a public DGA dataset, as an alternative to the entropy heuristic — not attempted, still a stretch goal

*Landed 2026-08-20. New `tldextract` runtime dependency (offline mode only). `analyze_pcap()` now runs a two-pass pipeline: Pass 1 (`build_dns_record()` per packet) produces provisional records, Pass 2 (`apply_detection_signals()`) computes batch-level baselines/bursts/ratios and finalizes each record's `remark`. Detection thresholds bundled into a new `DetectionSettings` dataclass (`settings_from_args()`) rather than passed as loose parameters, to keep `analyze_pcap()`'s signature stable as Phase 3 adds more. Records gained new JSON fields: `registrable_domain`, `subdomain`, `entropy_z_score`, `timestamp`, `subdomain_burst`, `subdomain_burst_unique_count`, `host_nxdomain_ratio`. Test suite grew from 31 to 64 cases, plus an end-to-end smoke test against a synthetic pcap covering normal/tunneling-burst/DGA-NXDOMAIN traffic. See DOCUMENTATION.md §1.3c for the full design writeup and §1.4 for new known limitations (hard time-window boundaries, no cross-run persistence).*

---

## Phase 3 — Threat Intelligence Integration ✅ *done*

**Why:** turns "looks suspicious" into "confirmed malicious" — the credibility jump that makes this tool usable in a real workflow instead of just a heuristic demo.

- [x] URLhaus feed lookup for resolved domains/IPs — `_fetch_urlhaus()`/`ThreatIntelChecker._check_urlhaus()`; requires a free `Auth-Key` (discovered via live testing — see below), skipped cleanly if not configured (`--urlhaus-api-key`)
- [x] OpenPhish feed lookup — `OpenPhishFeed`, free/keyless, refreshed hourly, verified against the live feed
- [x] Optional VirusTotal API integration (rate-limited free tier) — `_fetch_virustotal()`; `--virustotal-api-key`; client-side rate limiting (`virustotal_min_interval_seconds`, `virustotal_max_lookups_per_run`) that **skips** rather than blocks/sleeps once the limit is hit
- [x] Local IOC cache (avoid re-querying feeds for the same domain within a TTL window) — `IOCCache`, `--threat-intel-cache-ttl-seconds`; caches both malicious *and* clean verdicts (most domains are clean, so caching only positives would miss most of the benefit)
- [x] (Not originally scoped, done anyway) Module split into the `dns_analyzer/` package — see Phase 1's now-checked-off item above

*Landed 2026-08-20. New CLI flags: `--enable-threat-intel` (off by default — see privacy/opsec note below), `--urlhaus-api-key`/`URLHAUS_API_KEY`, `--virustotal-api-key`/`VIRUSTOTAL_API_KEY`, `--threat-intel-cache-ttl-seconds`. Records gained a `threat_intel` JSON field (verdict dict or `null`).*

*Real integration finding: while testing the live URLhaus API, discovered abuse.ch now requires an `Auth-Key` header on every request (401 with none, 403 `unknown_auth_key` with an invalid one) — older documentation describes it as keyless. `ThreatIntelChecker` checks for a configured key before attempting a URLhaus call at all, rather than shipping an integration that would silently fail on every request. Verified end-to-end against live OpenPhish/URLhaus APIs (not just injected test fakes) before landing. See DOCUMENTATION.md §1.3d for the full design writeup.*

*Also landed in this phase (not originally scoped, but the natural trigger point): split the ~630-line single file into the `dns_analyzer/` package (8 modules), deferred from Phase 1 as planned there. `Dns_Analyser.py` is now a thin backward-compatible shim; `python -m dns_analyzer` also works. Test suite reorganized to mirror the package (`tests/test_dns_parsing.py`, `test_detection.py`, `test_threat_intel.py`, `test_config.py`, `test_cli.py`, `test_analysis.py`) and grew from 64 to 95 cases, including a real synthetic-pcap end-to-end test in `test_analysis.py` (closing the "still open" test-coverage gap noted in Phase 1/2).*

---

## Phase 4 — Live/Streaming Capability ✅ *done*

**Why:** currently capture and analysis are two disconnected phases; this makes the tool actually useful for live monitoring, not just after-the-fact forensics.

- [x] Move detection inline into `packet_handler()` instead of only running post-capture — `--live`; `capture_dns_packets()` gained an `on_packet` hook, `detection.LiveDetectionEngine` reimplements baselining/burst/NXDOMAIN-ratio as streaming algorithms (Welford's online mean/variance, a sliding-window burst tracker, a running ratio counter), `live.py` orchestrates the same shape of JSON/PDF output as batch mode
- [x] Webhook alerting (Slack/Discord/email) on high-severity remarks — new `alerting.py`: `classify_severity()` + `WebhookAlerter`; `--enable-alerts`, `--webhook-url`/`DNS_ANALYZER_WEBHOOK_URL`, `--alert-min-severity` (info/medium/high/critical); works in both batch and live mode, sharing the same alerter
- [ ] (Stretch) live dashboard (Streamlit or Flask + simple JS chart) showing query volume, top domains, entropy distribution, active alerts — not attempted, still a stretch goal

*Landed 2026-08-20. New CLI flags: `--live`, `--enable-alerts`, `--webhook-url`, `--alert-min-severity`; `--duration 0` (or negative) now means "capture indefinitely until Ctrl+C" (works for both batch and live capture). Records gain a `severity` JSON field (`info`/`medium`/`high`/`critical`, always populated once detection runs, regardless of whether alerting is enabled). `capture_dns_packets()`'s `on_packet` hook is how live mode reuses the same, already-tested capture/error-handling code instead of duplicating it. `threat_intel.apply_threat_intel()` was split to expose a new `annotate_threat_intel()` single-record helper, reused by both the batch and live pipelines. Test suite grew from 95 to 153 cases, adding `tests/test_alerting.py`, `tests/test_capture.py` (via a monkeypatched `scapy.sniff()`), and `tests/test_live.py` (end-to-end live pipeline tests, same monkeypatching technique). Verified end-to-end with a real (non-mocked) engine run producing valid JSON/PDF output and correctly-timed inline webhook alerts. See DOCUMENTATION.md §1.2a/§1.3e/§1.3f for the full design writeup and §1.4 for new known limitations (live vs. batch z-score numerical difference, no alert de-duplication, synchronous `on_packet` capture-thread blocking).*

---

## Phase 5 — Interoperability ✅ *done*

**Why:** signals "plays well with a real SOC" rather than being a standalone script.

- [x] CSV export alongside JSON/PDF — new `export.py`: `generate_csv_report()`/`flatten_record()`; `--csv-file` (default `output.csv`), written automatically (no opt-in flag - it's a local file with no privacy implications)
- [x] Syslog/CEF output for SIEM forwarding (Splunk/ELK/Graylog) — new `syslog_forwarder.py`: `format_cef()`, `SyslogCefForwarder`; `--enable-syslog`, `--syslog-host`/`--syslog-port`/`--syslog-protocol`/`--syslog-min-severity`; works in both batch and live mode (live: fires inline per record, mirroring `WebhookAlerter`)
- [x] (Stretch) STIX/TAXII-formatted IOC export — **STIX 2.1 done** (`export.build_stix_bundle()`/`write_stix_bundle()`, `--export-stix`, `--stix-file`); **TAXII not attempted** - needs a real TAXII server + client library to integrate against, out of scope for a stretch item within a stretch phase; the STIX bundle file can still be manually uploaded to a TAXII server

*Landed 2026-08-20. New CLI flags: `--csv-file` (default `output.csv`, always written), `--enable-syslog`, `--syslog-host`, `--syslog-port` (default 514), `--syslog-protocol` (udp/tcp, default udp), `--syslog-min-severity` (default `info` - unlike `--alert-min-severity`'s `high` default, since SIEM forwarding is meant to be full-fidelity), `--export-stix`, `--stix-file` (default `output.stix.json`). Added `dns_analyzer/_version.py` (a leaf module, no imports) as the single source of truth for `__version__`, used in the CEF header's Device Version field. `analyze_pcap()`/`capture_and_detect_live()` both gained `csv_file`/`stix_file`/`syslog_forwarder` parameters. `cli.main()` now closes the syslog forwarder's socket in a `finally` block. Test suite grew from 153 to 190 cases, adding `tests/test_export.py` and `tests/test_syslog_forwarder.py`. Verified end-to-end against a real local UDP syslog socket (not just injected test fakes) - confirmed correct CEF formatting and escaping arriving over an actual network socket - plus real CSV/STIX file output. See DOCUMENTATION.md §1.3g/§1.3h for the full design writeup and §1.4 for new known limitations (UDP has no delivery guarantee, CEF Name field truncated at 200 chars, STIX bundle omits several fields a fully spec-compliant producer would include).*

---

## Phase 6 — Open Source Readiness ✅ *done*

**Why:** deferred deliberately until Phases 1–5 landed; this phase makes the repo genuinely contributor-ready now that there's real substance to contribute to.

- [x] `CONTRIBUTING.md` — dev setup, testing/linting, code conventions, a "suggested first contributions" list pulled from the project's own documented gaps (now linking to real filed issues - see below), plus a "Publishing a release" walkthrough for the PyPI trusted-publisher one-time setup
- [x] `CODE_OF_CONDUCT.md` (Contributor Covenant v2.1)
- [x] `SECURITY.md` — responsible-disclosure process, with an explicit threat-model section for this tool's specific attack surface (elevated capture privileges, untrusted-packet parsing, third-party data egress when threat-intel/alerting/syslog are enabled)
- [x] GitHub issue templates (bug report, feature request, a `config.yml` linking to `SECURITY.md`) + PR template
- [x] CI badge in the README *(landed early, as a natural side effect of Phase 1's CI setup)*
- [x] Demo GIF/screenshot of the PDF report and terminal run in the README — a real (synthetic-capture) screenshot of a flagged DNS-tunneling page plus curated real log output from a `--live --enable-alerts` run, both generated end-to-end through the actual pipeline, not mocked up
- [x] Tag a few small, well-scoped items as "good first issue" — **5 real issues filed** on GitHub (required enabling Issues on the repo first, which had been off): [#1 mypy in CI](https://github.com/eklavyamathur9/Dns-Analyser/issues/1), [#2 sliding-window burst backport](https://github.com/eklavyamathur9/Dns-Analyser/issues/2), [#3 alert de-duplication](https://github.com/eklavyamathur9/Dns-Analyser/issues/3), [#4 typosquatting detection](https://github.com/eklavyamathur9/Dns-Analyser/issues/4), [#5 live dashboard](https://github.com/eklavyamathur9/Dns-Analyser/issues/5)
- [x] `CHANGELOG.md` — Keep a Changelog format, one entry per landed phase (0.1.0 → 0.6.0), reconstructed from the git history
- [x] Package for PyPI (`pyproject.toml` build metadata) — verified end-to-end: built and installed into a throwaway venv, confirmed `dns_analyzer.__version__` resolves correctly (dynamically sourced from `_version.py`, not duplicated) and the `dns-analyzer` console-script entry point works. Also added `.github/workflows/publish.yml` (PyPI Trusted Publishing via OIDC, no stored secret) so a real release can ship with one click once set up. **Not yet actually published to PyPI** - claiming the package name is a real, external, one-way action requiring a one-time manual step on pypi.org only the account owner can do (documented in `CONTRIBUTING.md`), deliberately left for the user rather than attempted without their credentials.
- [x] Enable GitHub Discussions for design conversations separate from issues — enabled via `gh repo edit --enable-discussions`.

*Landed 2026-08-20. Confirmed `dns-analyzer`/`dns-analyser` are both unclaimed on PyPI (checked via the PyPI JSON API) before setting up packaging, so the name is safe to reserve whenever publishing happens. Creating the 5 "good first issue" tickets required first discovering (and enabling) that the repository had Issues disabled entirely - not just missing content. Semantic-versioning git tags for 0.1.0–0.6.0 were not created - `CHANGELOG.md` records the versions, but backdating tags onto existing commits is a bit unusual and was left out; new tags can start from whatever version ships next (see `CONTRIBUTING.md`'s release walkthrough).*

---

## Phase 7 — Naming / Rebrand *(deferred)*

**Why:** deferred until scope is clearer post-Phase 2/3 — renaming now would be premature. Candidates recorded here for later reference.

| Name | Rationale |
|---|---|
| **DNSpector** | DNS + Inspector — broad, fits both anomaly detection and general forensics scope |
| **Sentry53** | References port 53 + "sentry" (watch/guard) — memorable, security-forward |
| **DNSentinel** | DNS + Sentinel — straightforward, communicates active monitoring |
| **DNSleuth** | DNS + sleuth — catchy, leans into the investigative/forensic angle |
| **TunnelTrace** | Leans specifically into tunneling/exfiltration detection — narrower scope |
| **DGAWatch** | Leans specifically into DGA detection — narrower scope |

Leaning toward **DNSpector** or **Sentry53** if/when this happens, since the roadmap spans general DNS threat-hunting rather than one narrow technique — not decided.

---

## Suggested resume bullets (update as phases land)

- *"Built a Python-based DNS traffic analyzer implementing Shannon-entropy and behavioral-frequency heuristics to detect DGA malware and DNS-tunneling exfiltration, with automated JSON/PDF/SIEM-ready reporting."*
- *"Reduced false-positive rate on domain-anomaly detection by replacing a fixed entropy threshold with per-host statistical baselining (z-score deviation), and integrated public-suffix-aware domain parsing so entropy is scored on the registrant-controlled label instead of the full FQDN."* — Phase 2 ✅
- *"Implemented a DNS-tunneling detector based on unique-subdomain-burst frequency per parent domain — a signal independent of any single query's entropy — plus per-client NXDOMAIN-ratio tracking for DGA-infected-host detection."* — Phase 2 ✅
- *"Integrated OpenPhish/URLhaus/VirusTotal threat-intelligence feed lookups (with TTL caching and client-side rate limiting for VirusTotal's free tier) to convert heuristic alerts into confirmed IOC matches - opt-in, to keep an explicit boundary around what leaves the network."* — Phase 3 ✅
- *"Refactored a 630-line single-file script into an 8-module package once feature growth made the single file unwieldy, keeping a backward-compatible CLI entry point throughout."* — Phase 3 ✅
- *"Built a live/streaming detection mode using Welford's online algorithm and a sliding-window burst tracker to run the same statistical anomaly detection inline during capture instead of only after it completes, plus opt-in Slack-/Discord-compatible webhook alerting with severity classification."* — Phase 4 ✅
- *"Designed the live and batch detection pipelines to share their core per-record logic while only the statistical-aggregation strategy differs between them, and explicitly documented the resulting numerical difference (online vs. full-batch baselining) as a deliberate tradeoff."* — Phase 4 ✅
- *"Added CI (GitHub Actions) with a 150+-case pytest suite covering entropy scoring, DNS flag parsing, statistical detection (batch and streaming), threat-intel/alerting provider logic (via dependency-injected fake fetchers/senders), packet capture (via a monkeypatched scapy sniff()), and end-to-end synthetic-pcap tests for both pipelines."* — Phase 1 ✅ (test suite grown through every phase; CI wiring is Phase 1)
- *"Built CEF-formatted syslog forwarding for SIEM ingestion (Splunk/QRadar/ArcSight) and STIX 2.1 indicator export for threat-intel sharing, verified against a real UDP syslog listener socket end-to-end before landing, not just injected test fakes."* — Phase 5 ✅
- *"Prepared the project for open-source contribution (CONTRIBUTING/CODE_OF_CONDUCT/SECURITY docs, issue/PR templates, a changelog, PyPI packaging metadata) and verified the packaging end-to-end by building and installing into a clean virtual environment rather than assuming the metadata was correct."* — Phase 6 ✅
