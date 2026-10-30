"""JavaScript / TypeScript rules.

There's no JS parser in the Python standard library, so these rules run on a
"masked" copy of each line in which string, template and comment contents are
replaced with spaces. That keeps column positions intact while preventing
false positives from text inside strings or comments.
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

from ..models import Category, Fix, RuleContext, Severity, SourceFile, make_finding
from . import rule

JS = ("javascript", "typescript")

_MASK_CACHE: Dict[int, Tuple[List[str], List[str]]] = {}


def masked(src: SourceFile) -> Tuple[List[str], List[str]]:
    """Return (code_lines, comment_lines) with strings/comments blanked out.

    ``code_lines`` keeps quote characters but blanks their contents, so
    ``"a == b"`` becomes ``"      "``. ``comment_lines`` holds just the comment
    text of each line (for directive / TODO handling).
    """
    key = id(src)
    if key in _MASK_CACHE:
        return _MASK_CACHE[key]
    code_out: List[str] = []
    comment_out: List[str] = []
    state = None  # None | "'" | '"' | "`" | "block"
    for line in src.lines:
        code = []
        comment = []
        i = 0
        n = len(line)
        while i < n:
            ch = line[i]
            nxt = line[i + 1] if i + 1 < n else ""
            if state == "block":
                if ch == "*" and nxt == "/":
                    state = None
                    code.append("  ")
                    i += 2
                    continue
                comment.append(ch)
                code.append(" ")
            elif state in ("'", '"', "`"):
                if ch == "\\":
                    code.append("  "[: min(2, n - i)])
                    i += 2
                    continue
                if ch == state:
                    state = None
                    code.append(ch)
                else:
                    code.append(" ")
            else:
                if ch == "/" and nxt == "/":
                    comment.append(line[i + 2:])
                    code.append(" " * (n - i))
                    break
                if ch == "/" and nxt == "*":
                    state = "block"
                    code.append("  ")
                    i += 2
                    continue
                if ch in ("'", '"', "`"):
                    state = ch
                code.append(ch)
            i += 1
        if state in ("'", '"'):
            state = None  # unterminated single-line string; don't bleed into next line
        code_out.append("".join(code))
        comment_out.append("".join(comment))
    _MASK_CACHE[key] = (code_out, comment_out)
    return code_out, comment_out


def clear_cache() -> None:
    _MASK_CACHE.clear()


_LOOSE_EQ_RE = re.compile(r"(?<![=!<>])(==|!=)(?!=)")


@rule("JS001", "loose-equality", "`==`/`!=` perform type coercion; use `===`/`!==`.",
      category=Category.BUG, severity=Severity.WARNING, languages=JS, fixable=True)
def loose_equality(src: SourceFile, ctx: RuleContext):
    code, _ = masked(src)
    for i, line in enumerate(code, 1):
        for m in _LOOSE_EQ_RE.finditer(line):
            rest = line[m.end():].lstrip()
            before = line[:m.start()].rstrip()
            if rest.startswith("null") or before.endswith("null"):
                continue  # `x == null` is the idiomatic null-or-undefined check
            strict = m.group(1) + "="
            orig = src.line_text(i)
            fixed = orig[:m.start()] + strict + orig[m.end():]
            yield make_finding(loose_equality.rule, src, i,
                               f"Use `{strict}` instead of `{m.group(1)}` to avoid implicit type coercion.",
                               column=m.start() + 1, fix=Fix(i, fixed))
            break  # one per line keeps fixes non-overlapping


_CONSOLE_RE = re.compile(r"\bconsole\.(log|debug|trace|dir)\s*\(")


@rule("JS002", "console-log", "Leftover console logging.",
      category=Category.MAINTAINABILITY, severity=Severity.WARNING, languages=JS)
def console_log(src: SourceFile, ctx: RuleContext):
    if re.search(r"(^|/)(scripts?|bin|cli)/|\.(test|spec)\.[jt]sx?$", src.path):
        return  # CLIs and tests legitimately print
    code, _ = masked(src)
    for i, line in enumerate(code, 1):
        m = _CONSOLE_RE.search(line)
        if m:
            yield make_finding(console_log.rule, src, i, f"`console.{m.group(1)}()` left in code.",
                               column=m.start() + 1,
                               suggestion="Remove it or use the project's logger.")


@rule("JS003", "debugger-statement", "`debugger` statement left in code.",
      category=Category.BUG, severity=Severity.ERROR, languages=JS, fixable=True)
def debugger_statement(src: SourceFile, ctx: RuleContext):
    code, _ = masked(src)
    for i, line in enumerate(code, 1):
        m = re.search(r"\bdebugger\b\s*;?", line)
        if m:
            alone = line.strip() in ("debugger", "debugger;")
            yield make_finding(debugger_statement.rule, src, i, "`debugger` will pause execution in the browser.",
                               column=m.start() + 1, fix=Fix(i, None) if alone else None)


@rule("JS004", "no-var", "`var` is function-scoped and hoisted; prefer `let`/`const`.",
      category=Category.STYLE, severity=Severity.INFO, languages=JS)
def no_var(src: SourceFile, ctx: RuleContext):
    code, _ = masked(src)
    for i, line in enumerate(code, 1):
        m = re.search(r"(^|[;{(\s])var\s+[A-Za-z_$]", line)
        if m:
            yield make_finding(no_var.rule, src, i, "Use `let` or `const` instead of `var`.",
                               column=m.start() + 2 if m.group(1) else 1)


@rule("JS005", "await-in-loop", "Sequential `await` inside a loop; independent work could run in parallel.",
      category=Category.PERFORMANCE, severity=Severity.INFO, languages=JS)
def await_in_loop(src: SourceFile, ctx: RuleContext):
    code, _ = masked(src)
    loop_depths: List[int] = []  # brace depth at which each open loop body started
    depth = 0
    pending_loop = False
    reported_loops = set()
    for i, line in enumerate(code, 1):
        if re.search(r"\b(for|while)\s*\(", line) and not re.search(r"\bfor\s+await\b", line):
            pending_loop = True
        for ch in line:
            if ch == "{":
                depth += 1
                if pending_loop:
                    loop_depths.append(depth)
                    pending_loop = False
            elif ch == "}":
                if loop_depths and loop_depths[-1] == depth:
                    loop_depths.pop()
                depth = max(0, depth - 1)
        if loop_depths and re.search(r"\bawait\b", line) and loop_depths[-1] not in reported_loops:
            # Allow `await` on a promise collected in the loop, e.g. explicit throttling.
            reported_loops.add(loop_depths[-1])
            yield make_finding(await_in_loop.rule, src, i,
                               "`await` inside a loop runs each iteration one after another.",
                               column=line.find("await") + 1,
                               suggestion="If iterations are independent, collect promises and "
                                          "`await Promise.all(...)`.")
        if not loop_depths:
            reported_loops.clear()


@rule("JS006", "empty-catch", "Empty `catch` block silently swallows errors.",
      category=Category.BUG, severity=Severity.WARNING, languages=JS)
def empty_catch(src: SourceFile, ctx: RuleContext):
    code, comments = masked(src)
    joined = "\n".join(code)
    for m in re.finditer(r"\bcatch\s*(\([^)]*\))?\s*\{\s*\}", joined):
        line = joined.count("\n", 0, m.start()) + 1
        if comments[line - 1].strip():
            continue  # an explanatory comment counts as intentional
        yield make_finding(empty_catch.rule, src, line, "Empty catch block hides failures.",
                           suggestion="Handle, log, or rethrow the error (or comment why it's safe to ignore).")


@rule("JS007", "quote-style", "String quotes don't match the project's preferred quote style.",
      category=Category.STYLE, severity=Severity.INFO, languages=JS)
def js_quote_style(src: SourceFile, ctx: RuleContext):
    if ctx.quote_style not in ("single", "double"):
        return
    want, other = ("'", '"') if ctx.quote_style == "single" else ('"', "'")
    code, _ = masked(src)
    for i, line in enumerate(code, 1):
        idx = line.find(other)
        if idx == -1:
            continue
        raw = src.line_text(i)
        end = line.find(other, idx + 1)
        literal = raw[idx + 1:end] if end != -1 else ""
        if want in literal:
            continue  # switching quotes would require escaping
        yield make_finding(js_quote_style.rule, src, i,
                           f"Use {ctx.quote_style} quotes for consistency with the project style.",
                           column=idx + 1)


@rule("JS008", "ts-any", "Explicit `any` disables type checking.",
      category=Category.MAINTAINABILITY, severity=Severity.INFO, languages=("typescript",))
def ts_any(src: SourceFile, ctx: RuleContext):
    code, _ = masked(src)
    for i, line in enumerate(code, 1):
        m = re.search(r"(:\s*any\b|<any>|\bas\s+any\b|any\[\])", line)
        if m:
            yield make_finding(ts_any.rule, src, i, "Explicit `any` type.", column=m.start() + 1,
                               suggestion="Use `unknown` and narrow it, or a precise type.")
