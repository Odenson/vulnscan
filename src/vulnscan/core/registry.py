"""Registry that maps scanner names to scanner classes."""

from __future__ import annotations

from ..scanners import ALL_SCANNERS
from ..scanners.base import Scanner


def available_scanners() -> dict[str, type[Scanner]]:
    """Return {name: scanner_class} for every registered scanner."""
    return {cls.name: cls for cls in ALL_SCANNERS}


def resolve(names: list[str] | None) -> list[Scanner]:
    """Instantiate the requested scanners (or all, if ``names`` is falsy)."""
    registry = available_scanners()
    if not names:
        return [cls() for cls in registry.values()]

    chosen: list[Scanner] = []
    unknown: list[str] = []
    for name in names:
        cls = registry.get(name)
        if cls is None:
            unknown.append(name)
        else:
            chosen.append(cls())
    if unknown:
        raise KeyError(
            f"Unknown scanner(s): {', '.join(unknown)}. "
            f"Available: {', '.join(sorted(registry))}"
        )
    return chosen
