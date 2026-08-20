"""Backward-compatible entry point.

The implementation now lives in the dns_analyzer package (dns_parsing,
detection, threat_intel, capture, report, analysis, cli - see
DOCUMENTATION.md section 1 for the module map). This file exists so
`python Dns_Analyser.py` keeps working exactly as before; `python -m
dns_analyzer` works identically.
"""

from dns_analyzer.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
