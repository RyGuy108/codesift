"""Applies safe automatic fixes."""

from __future__ import annotations

import difflib
from typing import Dict, List, Tuple

from .models import Finding, SourceFile


def apply_fixes(src: SourceFile, findings: List[Finding]) -> Tuple[str, int]:
    """Return (new_text, applied_count). At most one fix per line per pass."""
    newline = "\r\n" if "\r\n" in src.text else "\n"
    lines = list(src.lines)
    had_final_newline = src.text.endswith(("\n", "\r"))
    force_final_newline = False
    by_line: Dict[int, Finding] = {}
    for f in findings:
        if f.fix is None or f.path != src.path:
            continue
        if f.rule_id == "G002":
            force_final_newline = True
            continue
        by_line.setdefault(f.fix.line, f)

    applied = int(force_final_newline)
    for lineno in sorted(by_line, reverse=True):
        fix = by_line[lineno].fix
        if not 1 <= lineno <= len(lines):
            continue
        if fix.replacement is None:
            del lines[lineno - 1]
        else:
            lines[lineno - 1] = fix.replacement
        applied += 1

    text = newline.join(lines)
    if lines and (had_final_newline or force_final_newline):
        text += newline
    return text, applied


def unified_diff(path: str, old: str, new: str) -> str:
    return "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
                                        fromfile=f"a/{path}", tofile=f"b/{path}"))
