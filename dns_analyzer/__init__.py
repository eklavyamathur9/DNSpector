"""DNS Analyzer - capture and analyze DNS traffic for anomalies such as
DNS tunneling and DGA-generated domains.
"""

from dns_analyzer._version import __version__
from dns_analyzer.cli import main

__all__ = ["main", "__version__"]
