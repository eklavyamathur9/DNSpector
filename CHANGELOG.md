# Changelog

All notable changes to this project are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is [SemVer](https://semver.org/)-ish (minor bump per completed roadmap phase, while the project is pre-1.0). See [PHASES.md](PHASES.md) for the full roadmap and [DOCUMENTATION.md](DOCUMENTATION.md) for the design rationale behind each change.

No git tags exist yet for the versions below - they're recorded here retroactively as of Phase 6. Tags will be added going forward as versions ship.

## [Unreleased]

### Added
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, GitHub issue/PR templates, this changelog, and PyPI packaging metadata (`pyproject.toml`) - open-source readiness (Phase 6).

## [0.6.0] - 2026-08-20 (Phase 5 - Interoperability)

### Added
- CSV export alongside JSON/PDF (`--csv-file`, written by default).
- Syslog/CEF forwarding for SIEM ingestion (`--enable-syslog`, `--syslog-host`/`-port`/`-protocol`/`-min-severity`), over UDP or TCP; works in both batch and `--live` mode.
- STIX 2.1 indicator bundle export for threat-intel-confirmed-malicious domains (`--export-stix`, `--stix-file`).

## [0.5.0] - 2026-08-20 (Phase 4 - Live/Streaming Capability)

### Added
- `--live` mode: runs detection inline as each packet is captured, using streaming/incremental algorithms (Welford's online mean/variance for entropy baselining, a sliding-window subdomain-burst tracker, a running NXDOMAIN-ratio counter) instead of batch mode's full-batch recompute.
- `--duration 0` (or negative) captures indefinitely until interrupted with Ctrl+C.
- Opt-in webhook alerting (`--enable-alerts`, `--webhook-url`, `--alert-min-severity`) - Slack-/Discord-compatible, works in both batch and live mode.
- Records gain a `severity` field (`info`/`medium`/`high`/`critical`).

### Changed
- Documented (not "fixed" - a deliberate tradeoff) that live and batch mode can produce different entropy z-scores for the same data, since live mode can only score against prior history, not a full-batch baseline.

## [0.4.0] - 2026-08-20 (Phase 3 - Threat Intelligence Integration)

### Added
- Threat-intel checks against OpenPhish (free), URLhaus (needs a free Auth-Key), and VirusTotal (needs a free API key), opt-in via `--enable-threat-intel`.
- Local TTL cache for threat-intel verdicts (caches both malicious and clean results).

### Changed
- Split the single ~630-line `Dns_Analyser.py` into the `dns_analyzer/` package (8 modules at the time). `Dns_Analyser.py` became a thin backward-compatible shim.

## [0.3.0] - 2026-08-20 (Phase 2 - Detection Quality Core)

### Added
- Per-host statistical baselining (z-score) as an additional signal alongside the fixed entropy threshold.
- Subdomain-burst detection (unique subdomains under one parent domain within a time window) - a DNS-tunneling signal independent of entropy.
- Per-client NXDOMAIN-ratio tracking - a DGA-infected-host signal.
- Public-suffix-aware domain parsing (`tldextract`), so entropy is scored on the registrant-controlled label instead of the full FQDN including TLD.

## [0.2.0] - 2026-08-20 (Phase 1 - Engineering Foundations)

### Added
- `argparse`-based CLI, replacing the original interactive `input()` prompt.
- JSON config file support (`--config`).
- `logging`-based output, replacing `print()`.
- GitHub Actions CI (lint + test on every push/PR).

### Fixed
- Realistic failure modes (capture permission errors, missing/corrupt pcap files, packets without an IP layer) now degrade gracefully instead of crashing with an unhandled traceback.

## [0.1.0] - 2026-08-20 (Phase 0 - Housekeeping)

### Fixed
- `parse_dns_flags()` opcode/rcode `IndexError` crash on uncommon DNS values.
- `calculate_entropy()` divide-by-zero on an empty domain.
- RCODE names corrected to standard DNS terminology.

### Added
- Initial `pytest` test suite.
