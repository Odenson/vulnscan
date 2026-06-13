"""Base class every scanner inherits from."""

from __future__ import annotations

from ..core.models import Finding, Project


class Scanner:
    """A pluggable scan unit.

    Each scanner declares a stable ``name`` (used in reports, the registry,
    and the matching SKILL.md), decides whether it ``applies_to`` a given
    project, and yields :class:`Finding` objects from ``scan``.
    """

    name: str = "base"
    description: str = ""

    def applies_to(self, project: Project) -> bool:  # noqa: ARG002
        return True

    def scan(self, project: Project) -> list[Finding]:
        raise NotImplementedError
