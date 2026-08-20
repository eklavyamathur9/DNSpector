# Contributing to DNSpector

Thanks for considering a contribution! This is a personal/portfolio project, but it's built to a "real project" standard - tested, linted, documented - and genuinely welcomes outside contributions.

## Ways to contribute

- **Bug reports** - see [Reporting bugs](#reporting-bugs) below. For security vulnerabilities, see [SECURITY.md](SECURITY.md) instead of opening a public issue.
- **Feature requests / ideas** - especially anything from the "still open" items in [PHASES.md](PHASES.md) or [DOCUMENTATION.md](DOCUMENTATION.md)'s known-limitations sections (§1.4) - those are curated lists of genuine gaps, not just aspirational wishlists.
- **Pull requests** - see [Dev setup](#dev-setup) and [Submitting a pull request](#submitting-a-pull-request) below.
- **Documentation** - [DOCUMENTATION.md](DOCUMENTATION.md) is meant to explain *why*, not just *what*; if something reads as unclear or stale, that's worth a PR on its own.

## Dev setup

```bash
git clone https://github.com/eklavyamathur9/DNSpector.git
cd DNSpector
python -m venv venv && source venv/bin/activate  # optional but recommended
pip install -r requirements-dev.txt
```

Run the tool itself with `sudo python dnspector.py` (raw packet capture needs elevated privileges) - see [README.md](README.md) for the full CLI.

## Running tests

```bash
pytest tests/ -v
```

The suite is organized to mirror the `dnspector/` package (`tests/test_detection.py` tests `dnspector/detection.py`, and so on). It runs with **zero real network access, root privileges, or webhook/syslog endpoints required** - every network-touching component (`threat_intel.py`, `alerting.py`, `syslog_forwarder.py`) takes an injectable function for the actual send/fetch, and tests supply a fake one. `tests/test_capture.py`/`tests/test_live.py` similarly monkeypatch `scapy.sniff()` rather than doing a real capture. If you add code that touches the network or capture, follow this pattern rather than mocking at the `unittest.mock` level or skipping the test in CI.

CI runs the same suite plus lint on every push/PR - see `.github/workflows/ci.yml`.

## Linting

```bash
ruff check .
```

Config lives in `pyproject.toml`. Fix what `ruff` flags before opening a PR; CI will fail otherwise.

## Code style / conventions

Skim [DOCUMENTATION.md](DOCUMENTATION.md) section 1 first - it's a full module-by-module walkthrough of *why* things are structured the way they are, which is more useful than a style guide for getting a PR to fit naturally. A few patterns worth knowing before you start:

- **Type hints throughout.** New functions should have them.
- **Dependency injection for anything network-touching**, so it stays testable without a real network (see `threat_intel.py`'s `urlhaus_fetcher`/`openphish_feed`/`virustotal_fetcher` params, or `alerting.py`'s `sender` param, for the established pattern).
- **Settings live in small `@dataclass`es** (`DetectionSettings`, `ThreatIntelSettings`, `AlertSettings`, `SyslogSettings`), not loose function parameters - keeps the pipeline functions' signatures from growing unboundedly as features are added.
- **Comments explain *why*, not *what*.** A comment justifying a non-obvious choice (a workaround, a subtle invariant, a design tradeoff) is welcome; a comment restating what the next line of code obviously does is not.
- **Batch and live pipelines share their per-record logic** (`build_dns_record`, `annotate_threat_intel`, `classify_severity`) and only differ in how batch-level statistics are aggregated (full-batch recompute vs. incremental/streaming). If you're adding a new detection signal, consider from the start whether it needs both a batch and a streaming implementation - see `detection.py`'s `apply_detection_signals()` vs. `LiveDetectionEngine` for the existing pattern.
- **Self-critique known limitations honestly.** If you land a feature with a real limitation (like the live/batch z-score numerical difference documented in DOCUMENTATION.md §1.4), write it down explicitly rather than leaving it as a silent surprise for the next person.

## Submitting a pull request

- Keep PRs focused - one logical change per PR is much easier to review than a bundle of unrelated fixes.
- Make sure `pytest tests/ -v` and `ruff check .` are both clean.
- If you're closing an item from [PHASES.md](PHASES.md), check it off and add a short note in that phase's landing summary (see existing phases for the format) - but feel free to open a PR without touching PHASES.md at all for anything not on the roadmap.
- If your change affects documented behavior, update [DOCUMENTATION.md](DOCUMENTATION.md) and/or [README.md](README.md) in the same PR - stale docs are worse than no docs.
- Describe *why* the change is needed, not just what it does - the commit history in this repo leans toward explaining reasoning (see `git log` for examples), and PR descriptions should too.

## Suggested first contributions

Filed as real issues, labeled `good first issue`, pulled from the project's own documented gaps (see [DOCUMENTATION.md](DOCUMENTATION.md) §1.4 and §3, and [PHASES.md](PHASES.md) for full context on each):

- [#1 - Wire up `mypy` in CI alongside `ruff`](https://github.com/eklavyamathur9/DNSpector/issues/1)
- [#2 - Backport the sliding-window burst tracker to batch mode](https://github.com/eklavyamathur9/DNSpector/issues/2)
- [#3 - Alert/syslog-forward de-duplication (cooldown per host+alert-type)](https://github.com/eklavyamathur9/DNSpector/issues/3)
- [#4 - Typosquatting detection (Levenshtein distance against known-brand domains)](https://github.com/eklavyamathur9/DNSpector/issues/4)
- [#5 - Live dashboard (Streamlit or Flask) for `--live` mode](https://github.com/eklavyamathur9/DNSpector/issues/5)

None of these require deep familiarity with the whole codebase to start - each touches one or two files with existing test patterns to follow. See the [full issue list](https://github.com/eklavyamathur9/DNSpector/issues) for anything newer, or [Discussions](https://github.com/eklavyamathur9/DNSpector/discussions) to propose your own idea before writing code.

## Publishing a release (maintainers)

Releases publish to PyPI via `.github/workflows/publish.yml`, using PyPI's [Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (OIDC) - no API token is stored in this repo. **One-time setup**, done once by whoever owns the `dnspector` name on PyPI:

1. Create a PyPI account (or log in) at [pypi.org](https://pypi.org/), if you haven't already.
2. Go to [pypi.org/manage/account/publishing/](https://pypi.org/manage/account/publishing/) and add a new pending trusted publisher for a *new* project:
   - PyPI project name: `dnspector`
   - Owner: `eklavyamathur9`
   - Repository name: `DNSpector`
   - Workflow name: `publish.yml`
   - Environment name: `pypi`
3. That's it - no secret to copy anywhere.

**Every release after that**, just:

1. Bump `__version__` in `dnspector/_version.py` and add a `CHANGELOG.md` entry.
2. Tag it (`git tag v0.7.0 && git push --tags`) and [publish a GitHub Release](https://github.com/eklavyamathur9/DNSpector/releases/new) from that tag.
3. The `publish.yml` workflow builds and publishes to PyPI automatically once the Release is published.

## License

By contributing, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).
