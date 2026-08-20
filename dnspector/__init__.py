"""DNSpector - capture and analyze DNS traffic for anomalies such as
DNS tunneling and DGA-generated domains.
"""

from dnspector._version import __version__
from dnspector.cli import main

__all__ = ["main", "__version__"]
