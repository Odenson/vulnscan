"""Built-in scanners.

Add a new scanner by subclassing :class:`base.Scanner` and listing it in
``ALL_SCANNERS`` below. The CLI and registry pick it up automatically.
"""

from .base import Scanner
from .dependency_audit import DependencyAuditScanner
from .bad_practices import BadPracticesScanner
from .secrets import SecretsScanner

ALL_SCANNERS: list[type[Scanner]] = [
    DependencyAuditScanner,
    BadPracticesScanner,
    SecretsScanner,
]

__all__ = [
    "Scanner",
    "DependencyAuditScanner",
    "BadPracticesScanner",
    "SecretsScanner",
    "ALL_SCANNERS",
]
