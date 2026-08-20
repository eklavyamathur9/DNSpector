# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities **privately**, not via a public GitHub issue:

1. **Preferred:** use GitHub's private vulnerability reporting for this repository (Security tab → "Report a vulnerability"), if enabled.
2. **Fallback:** email **cmathur671@gmail.com** with a description of the issue, steps to reproduce, and its potential impact.

You should receive an acknowledgment within **5 business days**. This is a personal/portfolio project maintained on a best-effort basis, not a funded security team - please set expectations accordingly, but genuine vulnerabilities will be prioritized over other work.

Please do not publicly disclose a vulnerability (blog post, social media, public issue) until a fix has shipped or 90 days have passed, whichever comes first - standard coordinated disclosure practice.

## What's In Scope

This tool has a somewhat unusual threat model worth being explicit about, given what it does:

- **It requires elevated privileges to run** (raw packet capture needs root, or `CAP_NET_RAW` on Linux). A vulnerability that lets captured/parsed network data influence what the tool does *as a privileged process* (e.g. path traversal via a crafted DNS response into where output files are written, command injection, unsafe deserialization) is a serious finding and squarely in scope.
- **It parses untrusted network input.** Every DNS packet this tool processes comes from the network and is attacker-controllable if the attacker can reach a network segment being monitored. Most parsing goes through [scapy](https://scapy.net/) (report scapy-specific parsing bugs upstream), but this project's own code also decodes fields (`dnspector/dns_parsing.py`, `detection.py`) - a crash, hang, or unexpected behavior triggerable by a maliciously crafted DNS packet is in scope here.
- **It sends data to third-party services when threat-intel, alerting, or syslog forwarding are enabled** (OpenPhish, URLhaus, VirusTotal, a configured webhook, a configured syslog host). SSRF-style issues (e.g. a way to make the tool send data somewhere the operator didn't configure), API key handling issues (e.g. a key ending up somewhere it shouldn't, like logs or committed output files), or webhook/CEF-message injection are in scope.
- **Dependency vulnerabilities** in `scapy`, `numpy`, `reportlab`, or `tldextract` that are specifically reachable through this project's usage of them are worth reporting here too, even though the underlying fix likely belongs upstream.

## What's Out of Scope

- Vulnerabilities that require the reporter to already have root/administrator access to the machine running this tool (at that point they don't need this tool to do damage).
- The fact that this tool *requires* elevated privileges to capture packets at all - that's an inherent property of raw packet capture on every OS, not a bug in this project. (`SECURITY.md`-relevant *mitigations* for this, like documenting least-privilege setup via Linux capabilities instead of full root, are welcome as regular contributions - see [CONTRIBUTING.md](CONTRIBUTING.md).)
- Denial-of-service via simply sending it a very high volume of legitimate-looking traffic - this is a single-process analysis tool, not a production network appliance; performance issues are welcome as regular (public) issues, not security reports.

## Supported Versions

This project doesn't yet have stable release branches - only the latest `main` is supported. Security fixes will land on `main`; see [CHANGELOG.md](CHANGELOG.md) for what's shipped in each version.
