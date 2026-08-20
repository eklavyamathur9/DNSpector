---
name: Bug report
about: Something isn't working as documented
title: "[Bug] "
labels: bug
assignees: ''
---

**Note:** for a security vulnerability, please follow [SECURITY.md](../../SECURITY.md) instead of opening a public issue here.

## Describe the bug

A clear, concise description of what's wrong.

## To reproduce

Steps to reproduce, ideally including:
- The exact command / CLI flags you ran (`python Dns_Analyser.py ...`)
- Whether you're using batch mode or `--live`
- A minimal example pcap or capture scenario, if the bug depends on specific DNS traffic

## Expected behavior

What you expected to happen instead.

## Actual behavior

What actually happened - include the full error/traceback if there is one, and relevant log output (`--log-level DEBUG` is helpful here).

## Environment

- OS:
- Python version (`python --version`):
- `dns_analyzer` version / commit (`python -c "import dns_analyzer; print(dns_analyzer.__version__)"`):
- Relevant flags/config (threat-intel enabled? alerting? syslog? live mode?):

## Additional context

Anything else that seems relevant.
