"""Language-agnostic rules that run on every text file."""

from __future__ import annotations

import re

from ..models import Category, Fix, RuleContext, Severity, SourceFile, make_finding
from . import rule

# --------------------------------------------------------------------------
# Whitespace / formatting
# --------------------------------------------------------------------------


@rule("G001", "trailing-whitespace", "Line has trailing whitespace.",
      category=Category.STYLE, severity=Severity.INFO, fixable=True)
def trailing_whitespace(src: SourceFile, ctx: RuleContext):
    if not ctx.trim_trailing_whitespace or src.language == "markdown":
        return  # Markdown uses two trailing spaces as a hard line break.
    r = trailing_whitespace.rule
    for i, line in enumerate(src.lines, 1):
        stripped = line.rstrip(" \t")
        if stripped != line:
            yield make_finding(r, src, i, "Trailing whitespace.", column=len(stripped) + 1,
                               fix=Fix(i, stripped))


@rule("G002", "missing-final-newline", "File does not end with a newline.",
      category=Category.STYLE, severity=Severity.INFO, fixable=True)
def missing_final_newline(src: SourceFile, ctx: RuleContext):
    if ctx.insert_final_newline and src.text and not src.text.endswith(("\n", "\r")):
        n = len(src.lines)
        yield make_finding(missing_final_newline.rule, src, n, "No newline at end of file.",
                           fix=Fix(n, src.lines[-1]))


@rule("G003", "line-too-long", "Line exceeds the configured maximum length.",
      category=Category.STYLE, severity=Severity.INFO)
def line_too_long(src: SourceFile, ctx: RuleContext):
    limit = ctx.max_line_length
    if limit <= 0 or src.language in ("markdown", "json", "text"):
        return
    for i, line in enumerate(src.lines, 1):
        if len(line) > limit and not _is_unbreakable(line):
            yield make_finding(line_too_long.rule, src, i,
                               f"Line is {len(line)} characters (limit {limit}).",
                               column=limit + 1)


def _is_unbreakable(line: str) -> bool:
    """URLs and long string-free tokens can't reasonably be wrapped."""
    s = line.strip()
    return bool(re.search(r"https?://\S{40,}", s)) or (" " not in s)


@rule("G004", "inconsistent-indentation",
      "Indentation does not match the project's configured style (.editorconfig / .codesift.toml).",
      category=Category.STYLE, severity=Severity.WARNING, fixable=True)
def inconsistent_indentation(src: SourceFile, ctx: RuleContext):
    # Go (gofmt) and Makefiles mandate tabs regardless of project preference.
    if ctx.indent_style is None or src.language in ("markdown", "text", "makefile", "go"):
        return
    r = inconsistent_indentation.rule
    in_docstring = False
    for i, line in enumerate(src.lines, 1):
        # Don't police indentation inside Python triple-quoted strings.
        if src.language == "python" and (line.count('"""') + line.count("'''")) % 2 == 1:
            in_docstring = not in_docstring
            continue
        if in_docstring or not line.strip():
            continue
        indent = line[: len(line) - len(line.lstrip(" \t"))]
        if not indent:
            continue
        if ctx.indent_style == "space" and "\t" in indent:
            size = ctx.indent_size or 4
            fixed = indent.replace("\t", " " * size) + line[len(indent):]
            yield make_finding(r, src, i, "Tab used for indentation; project uses spaces.",
                               fix=Fix(i, fixed))
        elif ctx.indent_style == "tab" and " " in indent and not indent.startswith("\t"):
            yield make_finding(r, src, i, "Spaces used for indentation; project uses tabs.")


# --------------------------------------------------------------------------
# Correctness / security
# --------------------------------------------------------------------------

_CONFLICT_RE = re.compile(r"^(<{7}|={7}|>{7})(\s|$)")


@rule("G010", "merge-conflict-marker", "Unresolved git merge conflict marker.",
      category=Category.BUG, severity=Severity.ERROR)
def merge_conflict_marker(src: SourceFile, ctx: RuleContext):
    lines = src.lines
    has_open = any(l.startswith("<<<<<<<") for l in lines)
    if not has_open:
        return  # a lone "=======" is a valid RST/markdown underline
    for i, line in enumerate(lines, 1):
        if _CONFLICT_RE.match(line):
            yield make_finding(merge_conflict_marker.rule, src, i,
                               "Merge conflict marker left in file.")


_SECRET_PATTERNS = [
    ("AWS access key ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Stripe live key", re.compile(r"\b(sk|rk)_live_[A-Za-z0-9]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("OpenAI/Anthropic-style API key", re.compile(r"\bsk-(ant-)?[A-Za-z0-9_\-]{32,}\b")),
    ("Private key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY")),
]
_ASSIGNED_SECRET_RE = re.compile(
    r"""(?i)\b\w*?(password|passwd|secret|api_?key|access_?token|auth_?token)\b['"]?\s*[:=]\s*['"]([^'"\s]{8,})['"]"""
)
_PLACEHOLDER_RE = re.compile(r"(?i)(example|placeholder|changeme|your[_-]|xxx|dummy|test|\$\{|\{\{|<)")


@rule("G011", "hardcoded-secret", "Credential or private key committed to source.",
      category=Category.SECURITY, severity=Severity.ERROR,
      help_text="Move the value to an environment variable or secret manager and rotate it, "
                "since it is already in git history.")
def hardcoded_secret(src: SourceFile, ctx: RuleContext):
    r = hardcoded_secret.rule
    for i, line in enumerate(src.lines, 1):
        for label, pattern in _SECRET_PATTERNS:
            m = pattern.search(line)
            if m:
                yield make_finding(r, src, i, f"Possible {label} committed to source.",
                                   column=m.start() + 1,
                                   suggestion="Load it from an environment variable or secret store, "
                                              "and rotate the exposed credential.")
                break
        else:
            m = _ASSIGNED_SECRET_RE.search(line)
            if m and not _PLACEHOLDER_RE.search(m.group(2)):
                yield make_finding(r, src, i, f"Hard-coded value assigned to '{m.group(1)}'.",
                                   column=m.start() + 1,
                                   suggestion="Read it from configuration or the environment instead.")


_TODO_RE = re.compile(r"(#|//|/\*|<!--|--)\s*(TODO|FIXME|XXX|HACK)\b[:\s]?(.*)")


@rule("G020", "todo-comment", "TODO/FIXME comment (tracked so they don't get lost).",
      category=Category.MAINTAINABILITY, severity=Severity.INFO)
def todo_comment(src: SourceFile, ctx: RuleContext):
    for i, line in enumerate(src.lines, 1):
        m = _TODO_RE.search(line)
        if m:
            text = m.group(3).strip() or "(no description)"
            yield make_finding(todo_comment.rule, src, i, f"{m.group(2)}: {text}",
                               column=m.start(2) + 1)
