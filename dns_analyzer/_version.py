"""Single source of truth for the package version.

Kept in its own leaf module (no imports) so any module can import
__version__ - e.g. for a CEF Device Version field - without risking a
circular import through dns_analyzer/__init__.py.
"""

__version__ = "0.6.0"
