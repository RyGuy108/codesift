"""Rule registry.

Rules register themselves with the :func:`rule` decorator. Importing this
package imports every rule module so the registry is fully populated.
"""

from __future__ import annotations

from typing import Callable, Dict, Iterable

from ..models import Category, Rule, Severity

REGISTRY: Dict[str, Rule] = {}


def rule(rule_id: str, name: str, description: str, *, category: Category,
         severity: Severity = Severity.WARNING, languages: Iterable[str] = (),
         fixable: bool = False, help_text: str = "") -> Callable:
    """Register the decorated function as a rule implementation."""

    def decorator(func: Callable) -> Callable:
        if rule_id in REGISTRY:
            raise RuntimeError(f"duplicate rule id {rule_id}")
        REGISTRY[rule_id] = Rule(
            id=rule_id,
            name=name,
            description=description,
            category=category,
            default_severity=severity,
            languages=frozenset(languages),
            check=func,
            fixable=fixable,
            help_text=help_text or description,
        )
        # Let the implementation build findings referencing its own Rule.
        func.rule = REGISTRY[rule_id]
        return func

    return decorator


def all_rules() -> Dict[str, Rule]:
    return dict(REGISTRY)


# Populate the registry.
from . import generic, javascript, python  # noqa: E402,F401
