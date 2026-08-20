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

## Phase 1 — Engineering Foundations

**Why:** the tool currently only runs interactively and prints to stdout, which blocks scripting, CI, and any kind of automation — this phase makes it a proper CLI tool without touching detection logic.

- [ ] Replace `input()` with `argparse` (`--duration`, `--iface`, `--output-dir`, etc.)
- [ ] Replace `print()` with the `logging` module (levels + optional file output)
- [ ] Add a config file (YAML/JSON) for thresholds, interface, output paths, feed URLs
- [ ] Add type hints throughout
- [ ] Add error handling for realistic failure modes: missing capture permissions, no packets captured, malformed/empty pcap, missing `DNSQR` layer
- [ ] Add GitHub Actions CI: lint (`ruff`) + `pytest` on every push
- [ ] Split into modules (`capture.py`, `analysis.py`, `report.py`, `cli.py`) once the CLI/config work makes the single file unwieldy

---

## Phase 2 — Detection Quality Core

**Why:** this is the highest-value phase — it's the difference between "a script with an entropy check" and "a tool that understands DNS threats." See DOCUMENTATION.md §2.4 for the gap this closes.

- [ ] Replace the fixed entropy threshold (3.5) with per-host/per-domain statistical baselining (rolling mean/stddev, z-score deviation)
- [ ] Add query-frequency/burst analysis: unique subdomain-label count per parent domain per time window (tunneling signal independent of entropy)
- [ ] Track NXDOMAIN ratio per source host (classic DGA-infected-host indicator)
- [ ] Normalize domains against the public suffix / TLD before scoring entropy (score the attacker-controlled label, not the whole FQDN)
- [ ] (Stretch) small DGA classifier (n-gram/logistic regression) trained on a public DGA dataset, as an alternative to the entropy heuristic

---

## Phase 3 — Threat Intelligence Integration

**Why:** turns "looks suspicious" into "confirmed malicious" — the credibility jump that makes this tool usable in a real workflow instead of just a heuristic demo.

- [ ] URLhaus feed lookup for resolved domains/IPs
- [ ] OpenPhish feed lookup
- [ ] Optional VirusTotal API integration (rate-limited free tier)
- [ ] Local IOC cache (avoid re-querying feeds for the same domain within a TTL window)

---

## Phase 4 — Live/Streaming Capability

**Why:** currently capture and analysis are two disconnected phases; this makes the tool actually useful for live monitoring, not just after-the-fact forensics.

- [ ] Move detection inline into `packet_handler()` instead of only running post-capture
- [ ] Webhook alerting (Slack/Discord/email) on high-severity remarks
- [ ] (Stretch) live dashboard (Streamlit or Flask + simple JS chart) showing query volume, top domains, entropy distribution, active alerts

---

## Phase 5 — Interoperability

**Why:** signals "plays well with a real SOC" rather than being a standalone script.

- [ ] CSV export alongside JSON/PDF
- [ ] Syslog/CEF output for SIEM forwarding (Splunk/ELK/Graylog)
- [ ] (Stretch) STIX/TAXII-formatted IOC export

---

## Phase 6 — Open Source Readiness *(deferred — build first, open later)*

**Why:** deferred deliberately. Focus stays on Phases 1–3 landing first; this phase makes the repo genuinely contributor-ready once there's more substance to contribute to.

- [ ] `CONTRIBUTING.md` — dev setup, how to run tests, branch/PR conventions
- [ ] `CODE_OF_CONDUCT.md` (Contributor Covenant template)
- [ ] `SECURITY.md` — responsible-disclosure process (relevant: this tool needs elevated raw-capture privileges and touches potentially sensitive traffic)
- [ ] GitHub issue templates (bug report, feature request) + PR template
- [ ] CI badge + a demo GIF/screenshot of the PDF report and terminal run in the README (big discoverability lever)
- [ ] Tag a few small, well-scoped Phase 1/5 items as "good first issue"
- [ ] `CHANGELOG.md` + semantic versioning via git tags once phases start shipping
- [ ] Package for PyPI (`pyproject.toml`) so it's `pip install`-able without cloning
- [ ] Enable GitHub Discussions for design conversations separate from issues

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
- *"Reduced false-positive rate on domain-anomaly detection by replacing a fixed entropy threshold with per-host statistical baselining (z-score deviation)."* — Phase 2
- *"Integrated threat-intelligence feed lookups (URLhaus) to convert heuristic alerts into confirmed IOC matches."* — Phase 3
- *"Added CI (GitHub Actions) with a pytest suite covering entropy scoring, DNS flag parsing, and remark generation."* — Phase 1 (test suite already done in Phase 0; CI wiring is Phase 1)
