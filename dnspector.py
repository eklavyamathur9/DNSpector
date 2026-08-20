"""Root-level entry point.

The implementation lives in the dnspector package (dns_parsing,
detection, threat_intel, capture, report, analysis, cli - see
DOCUMENTATION.md section 1 for the module map). This file is a thin
wrapper so `python dnspector.py` works as a single-script-style
invocation without needing to `pip install` the package first;
`python -m dnspector` (and, once installed, the `dnspector` console
command) are equivalent.
"""

from dnspector.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
