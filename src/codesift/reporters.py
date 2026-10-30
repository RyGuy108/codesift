"""Output formats: text, json, sarif, github, markdown."""

from __future__ import annotations

import json
import os
import sys
from collections import Counter, defaultdict
from typing import Dict, List, Optional

from . import __version__
from .engine import RunResult
from .models import Category, Finding, Severity
from .rules import all_rules

COMMENT_MARKER = "<!-- codesift-report -->"
REPO_URL = "https://github.com/codesift/codesift"

# --------------------------------------------------------------------------
# Text (terminal)
# --------------------------------------------------------------------------

_COLORS = {"reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m", "red": "\033[31m",
           "yellow": "\033[33m", "blue": "\033[34m", "cyan": "\033[36m", "green": "\033[32m"}
_SEV_COLOR = {Severity.ERROR: "red", Severity.WARNING: "yellow", Severity.INFO: "blue"}


def _use_color(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR") or os.environ.get("GITHUB_ACTIONS"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


def format_text(result: RunResult, *, color: Optional[bool] = None, show_source: bool = True,
                stream=sys.stdout) -> str:
    color = _use_color(stream) if color is None else color

    def c(name: str, s: str) -> str:
        return f"{_COLORS[name]}{s}{_COLORS['reset']}" if color else s

    out: List[str] = []
    by_file: Dict[str, List[Finding]] = defaultdict(list)
    for f in result.findings:
        by_file[f.path].append(f)

    for path, findings in by_file.items():
        out.append(c("bold", c("cyan", path)))
        for f in findings:
            sev = c(_SEV_COLOR[f.severity], f"{f.severity.label:<7}")
            fix = c("green", " [fixable]") if f.fix else ""
            out.append(f"  {f.line:>4}:{f.column:<3} {sev} {c('dim', f.rule_id)}  {f.message}{fix}")
            if show_source and f.source_line.strip():
                src = f.source_line.rstrip()
                lead = len(src) - len(src.lstrip())
                out.append(c("dim", f"           │ {src.strip()[:140]}"))
                caret_pos = max(0, f.column - 1 - lead)
                if caret_pos < 140:
                    out.append(c("dim", "           │ ") + c(_SEV_COLOR[f.severity], " " * caret_pos + "^"))
            if f.suggestion:
                out.append(c("green", f"           ↳ {f.suggestion}"))
        out.append("")

    out.append(summary_line(result, color=color))
    for err in result.errors:
        out.append(c("red", f"internal error: {err}"))
    return "\n".join(out)


def summary_line(result: RunResult, *, color: bool = False) -> str:
    counts = result.counts()
    fixable = sum(1 for f in result.findings if f.fix)
    total = len(result.findings)
    if total == 0:
        hidden = f", {result.baselined} hidden by baseline" if result.baselined else ""
        files = f"{result.files_scanned} file{'s' if result.files_scanned != 1 else ''}"
        msg = f"✓ No issues found in {files} ({result.duration:.2f}s{hidden})."
        return f"{_COLORS['green']}{msg}{_COLORS['reset']}" if color else msg
    parts = [f"{counts.get(s.label, 0)} {s.label}{'s' if counts.get(s.label, 0) != 1 else ''}"
             for s in (Severity.ERROR, Severity.WARNING, Severity.INFO)]
    extra = []
    if fixable:
        extra.append(f"{fixable} auto-fixable with --fix")
    if result.baselined:
        extra.append(f"{result.baselined} hidden by baseline")
    if result.suppressed:
        extra.append(f"{result.suppressed} suppressed inline")
    tail = f" — {', '.join(extra)}" if extra else ""
    files = f"{result.files_scanned} file{'s' if result.files_scanned != 1 else ''}"
    return (f"✗ {total} issue{'s' if total != 1 else ''} ({', '.join(parts)}) in {files} "
            f"({result.duration:.2f}s){tail}.")


# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------


def format_json(result: RunResult) -> str:
    return json.dumps({
        "version": __version__,
        "summary": {
            "files_scanned": result.files_scanned,
            "total": len(result.findings),
            **{s.label: result.counts().get(s.label, 0) for s in Severity},
            "fixable": sum(1 for f in result.findings if f.fix),
            "suppressed": result.suppressed,
            "baselined": result.baselined,
            "duration_seconds": round(result.duration, 3),
        },
        "findings": [f.to_dict() for f in result.findings],
    }, indent=2)


# --------------------------------------------------------------------------
# SARIF 2.1.0 (GitHub code scanning)
# --------------------------------------------------------------------------

_SARIF_LEVEL = {Severity.ERROR: "error", Severity.WARNING: "warning", Severity.INFO: "note"}
_SECURITY_SEVERITY = {Severity.ERROR: "8.0", Severity.WARNING: "5.0", Severity.INFO: "2.0"}


def format_sarif(result: RunResult) -> str:
    rules = all_rules()
    used_ids = sorted({f.rule_id for f in result.findings} | set(rules))
    index = {rid: i for i, rid in enumerate(used_ids)}
    sarif_rules = []
    for rid in used_ids:
        r = rules.get(rid)
        if r is None:
            sarif_rules.append({"id": rid})
            continue
        tags = [r.category.value]
        props = {"tags": tags, "precision": "high" if r.category == Category.BUG else "medium"}
        if r.category == Category.SECURITY:
            props["security-severity"] = _SECURITY_SEVERITY[r.default_severity]
        sarif_rules.append({
            "id": r.id,
            "name": r.name,
            "shortDescription": {"text": r.description},
            "fullDescription": {"text": r.help_text},
            "help": {"text": r.help_text, "markdown": f"**{r.name}** — {r.help_text}"},
            "defaultConfiguration": {"level": _SARIF_LEVEL[r.default_severity]},
            "properties": props,
        })

    results = []
    for f in result.findings:
        msg = f.message + (f" Suggestion: {f.suggestion}" if f.suggestion else "")
        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": index[f.rule_id],
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": f.line, "startColumn": max(1, f.column),
                               "endLine": f.end_line or f.line},
                }
            }],
            "partialFingerprints": {"codesiftFingerprint/v1": f.fingerprint()},
        })

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "codesift", "version": __version__, "informationUri": REPO_URL,
                                "rules": sarif_rules}},
            "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///" + result_root_uri()}},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)


def result_root_uri() -> str:
    root = os.environ.get("GITHUB_WORKSPACE") or os.getcwd()
    return root.replace(os.sep, "/").lstrip("/") + "/"


# --------------------------------------------------------------------------
# GitHub Actions workflow commands (inline PR annotations)
# --------------------------------------------------------------------------

_GH_LEVEL = {Severity.ERROR: "error", Severity.WARNING: "warning", Severity.INFO: "notice"}


def _gh_escape(s: str, prop: bool = False) -> str:
    s = s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if prop:
        s = s.replace(":", "%3A").replace(",", "%2C")
    return s


def format_github(result: RunResult, max_annotations: int = 200) -> str:
    """`::error file=...` lines. GitHub shows at most ~50 per step per level, so
    we emit the most severe first."""
    lines = []
    ordered = sorted(result.findings, key=lambda f: (-f.severity, f.sort_key()))
    for f in ordered[:max_annotations]:
        title = _gh_escape(f"{f.rule_id} {all_rules()[f.rule_id].name}" if f.rule_id in all_rules() else f.rule_id,
                           prop=True)
        msg = f.message + (f"\n↳ {f.suggestion}" if f.suggestion else "")
        lines.append(f"::{_GH_LEVEL[f.severity]} file={_gh_escape(f.path, True)},line={f.line},"
                     f"col={f.column},endLine={f.end_line or f.line},title={title}::{_gh_escape(msg)}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Markdown (PR comment / job summary)
# --------------------------------------------------------------------------

_SEV_EMOJI = {Severity.ERROR: "🔴", Severity.WARNING: "🟡", Severity.INFO: "🔵"}
_CAT_EMOJI = {Category.BUG: "🐛", Category.PERFORMANCE: "⚡", Category.STYLE: "🎨",
              Category.SECURITY: "🔒", Category.MAINTAINABILITY: "🧹"}


def format_markdown(result: RunResult, *, max_rows: int = 150, link_base: Optional[str] = None,
                    title: str = "codesift report", fail_on: Optional[Severity] = Severity.ERROR) -> str:
    """Render a report suitable for a sticky PR comment or $GITHUB_STEP_SUMMARY.

    ``link_base`` (e.g. ``https://github.com/o/r/blob/<sha>``) turns locations into links.
    """
    counts = result.counts()
    cats = Counter(f.category for f in result.findings)
    total = len(result.findings)
    failing = fail_on is not None and any(f.severity >= fail_on for f in result.findings)
    policy = f"fails on `{fail_on.label}` and above" if fail_on is not None else "report only"
    status = "❌ **Failing**" if failing else ("⚠️ **Passing with issues**" if total else "✅ **All clear**")

    md = [COMMENT_MARKER, f"## 🔎 {title}", ""]
    md.append(f"{status} — {total} issue{'s' if total != 1 else ''} across {result.files_scanned} "
              f"file{'s' if result.files_scanned != 1 else ''} scanned "
              f"({policy}).")
    md.append("")
    if total:
        md.append("| Severity | Count | | Category | Count |")
        md.append("|---|---:|---|---|---:|")
        sev_rows = [(f"{_SEV_EMOJI[s]} {s.label}", counts.get(s.label, 0))
                    for s in (Severity.ERROR, Severity.WARNING, Severity.INFO)]
        cat_rows = [(f"{_CAT_EMOJI[c]} {c.value}", cats.get(c, 0)) for c in Category]
        for i in range(max(len(sev_rows), len(cat_rows))):
            a = sev_rows[i] if i < len(sev_rows) else ("", "")
            b = cat_rows[i] if i < len(cat_rows) else ("", "")
            md.append(f"| {a[0]} | {a[1]} | | {b[0]} | {b[1]} |")
        md.append("")

        fixable = sum(1 for f in result.findings if f.fix)
        if fixable:
            md.append(f"> 🛠️ **{fixable}** of these can be fixed automatically: run `codesift --fix` locally.")
            md.append("")

        md.append("<details open><summary><b>Findings</b></summary>")
        md.append("")
        md.append("| | Location | Rule | Message |")
        md.append("|---|---|---|---|")
        ordered = sorted(result.findings, key=lambda f: (-f.severity, f.sort_key()))
        for f in ordered[:max_rows]:
            loc = f"{f.path}:{f.line}"
            if link_base:
                loc = f"[{loc}]({link_base}/{f.path}#L{f.line})"
            else:
                loc = f"`{loc}`"
            msg = f.message.replace("|", "\\|")
            if f.suggestion:
                suggestion = f.suggestion.replace("|", "\\|")
                msg += f"<br><sub>↳ {suggestion}</sub>"
            md.append(f"| {_SEV_EMOJI[f.severity]} | {loc} | `{f.rule_id}` | {msg} |")
        if total > max_rows:
            md.append("")
            md.append(f"_…and {total - max_rows} more. See the job log or the Code Scanning tab for the full list._")
        md.append("")
        md.append("</details>")
        md.append("")

    notes = []
    if result.baselined:
        notes.append(f"{result.baselined} pre-existing issue(s) hidden by the baseline")
    if result.filtered_by_diff:
        notes.append(f"{result.filtered_by_diff} issue(s) outside changed lines not shown")
    if result.suppressed:
        notes.append(f"{result.suppressed} suppressed with `codesift: ignore`")
    if notes:
        md.append(f"<sub>{' · '.join(notes)}.</sub>")
        md.append("")
    md.append(f"<sub>codesift v{__version__} · {result.duration:.2f}s</sub>")
    return "\n".join(md)


FORMATTERS = {
    "text": format_text,
    "json": format_json,
    "sarif": format_sarif,
    "github": format_github,
    "markdown": format_markdown,
}
