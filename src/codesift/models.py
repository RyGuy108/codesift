"""Core data types shared across codesift."""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional


class Severity(enum.IntEnum):
    """Severity levels, ordered so they can be compared (`ERROR > WARNING`)."""

    INFO = 1
    WARNING = 2
    ERROR = 3

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {valid})") from exc

    @property
    def label(self) -> str:
        return self.name.lower()


class Category(str, enum.Enum):
    """What kind of problem a rule detects."""

    BUG = "bug"                  # very likely incorrect behaviour
    PERFORMANCE = "performance"  # works, but wastes time/memory
    STYLE = "style"              # consistency / readability
    SECURITY = "security"        # leaked secrets, unsafe calls
    MAINTAINABILITY = "maintainability"  # complexity, dead code


@dataclass(frozen=True)
class Fix:
    """A single-line textual replacement that resolves a finding.

    `line` is 1-based. The fixer replaces the full text of that line with
    `replacement` (which must not include a trailing newline). A
    replacement of ``None`` deletes the line.
    """

    line: int
    replacement: Optional[str]


@dataclass
class Finding:
    rule_id: str
    message: str
    path: str  # repository-relative, forward slashes
    line: int
    column: int = 1
    end_line: Optional[int] = None
    severity: Severity = Severity.WARNING
    category: Category = Category.STYLE
    suggestion: Optional[str] = None
    fix: Optional[Fix] = None
    source_line: str = ""

    def fingerprint(self) -> str:
        """Stable identity used by baselines and SARIF.

        Deliberately excludes the line number so findings survive unrelated
        edits that shift code up or down.
        """
        basis = f"{self.rule_id}|{self.path}|{self.source_line.strip()}|{self.message}"
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:20]

    def sort_key(self):
        return (self.path, self.line, self.column, self.rule_id)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule_id,
            "severity": self.severity.label,
            "category": self.category.value,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line or self.line,
            "message": self.message,
            "suggestion": self.suggestion,
            "fixable": self.fix is not None,
            "fingerprint": self.fingerprint(),
        }


@dataclass
class SourceFile:
    """A file loaded for analysis."""

    path: str        # repo-relative, forward slashes
    abs_path: str
    text: str
    language: str    # "python", "javascript", "typescript", "text", ...

    _lines: Optional[list] = field(default=None, repr=False)

    @property
    def lines(self) -> list:
        if self._lines is None:
            self._lines = self.text.splitlines()
        return self._lines

    def line_text(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1]
        return ""


@dataclass(frozen=True)
class Rule:
    """Metadata + implementation for one check."""

    id: str
    name: str
    description: str
    category: Category
    default_severity: Severity
    languages: frozenset  # empty = all languages
    check: Callable  # (SourceFile, RuleContext) -> Iterable[Finding]
    fixable: bool = False
    help_text: str = ""

    def applies_to(self, language: str) -> bool:
        return not self.languages or language in self.languages


@dataclass
class RuleContext:
    """Per-run settings exposed to rules (derived from config/.editorconfig)."""

    max_line_length: int = 120
    indent_style: Optional[str] = None  # "space" | "tab" | None (don't check)
    indent_size: Optional[int] = None
    max_complexity: int = 12
    max_function_length: int = 80
    max_arguments: int = 7
    insert_final_newline: bool = True
    trim_trailing_whitespace: bool = True
    quote_style: Optional[str] = None  # "single" | "double" | None
    options: dict = field(default_factory=dict)


def make_finding(rule: Rule, src: SourceFile, line: int, message: str, *, column: int = 1,
                 end_line: Optional[int] = None, suggestion: Optional[str] = None,
                 fix: Optional[Fix] = None) -> Finding:
    return Finding(
        rule_id=rule.id,
        message=message,
        path=src.path,
        line=line,
        column=column,
        end_line=end_line,
        severity=rule.default_severity,
        category=rule.category,
        suggestion=suggestion,
        fix=fix,
        source_line=src.line_text(line),
    )


FindingIter = Iterable[Finding]
