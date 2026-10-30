"""Python rules built on the standard-library ``ast`` module."""

from __future__ import annotations

import ast
import builtins
import re
from typing import Dict, Iterator, Optional, Set

from ..models import Category, Fix, RuleContext, Severity, SourceFile, make_finding
from . import rule

PY = ("python",)

# The AST is parsed once per file and cached here for the duration of a run.
_AST_CACHE: Dict[int, Optional[ast.AST]] = {}


def parse(src: SourceFile) -> Optional[ast.AST]:
    key = id(src)
    if key not in _AST_CACHE:
        try:
            _AST_CACHE[key] = ast.parse(src.text, filename=src.path, type_comments=False)
        except (SyntaxError, ValueError):
            _AST_CACHE[key] = None
    return _AST_CACHE[key]


_NODES_CACHE: Dict[int, list] = {}


def _all_nodes(tree: ast.AST) -> list:
    """Every node in the tree, computed once per file (rules iterate it many times)."""
    key = id(tree)
    if key not in _NODES_CACHE:
        _NODES_CACHE[key] = list(ast.walk(tree))
    return _NODES_CACHE[key]


def clear_cache() -> None:
    _AST_CACHE.clear()
    _NODES_CACHE.clear()


FUNC_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef)
LOOP_TYPES = (ast.For, ast.AsyncFor, ast.While)


def _walk_scope(node: ast.AST) -> Iterator[ast.AST]:
    """Walk a function body without descending into nested functions/classes."""
    stack = list(ast.iter_child_nodes(node))
    while stack:
        child = stack.pop()
        yield child
        if not isinstance(child, (*FUNC_TYPES, ast.ClassDef, ast.Lambda)):
            stack.extend(ast.iter_child_nodes(child))


def _name(node: ast.AST) -> str:
    """Dotted name of a Name/Attribute chain, '' otherwise."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return f"{base}.{node.attr}" if base else ""
    return ""


# --------------------------------------------------------------------------
# Bugs
# --------------------------------------------------------------------------


@rule("PY001", "syntax-error", "File cannot be parsed as Python.",
      category=Category.BUG, severity=Severity.ERROR, languages=PY)
def syntax_error(src: SourceFile, ctx: RuleContext):
    try:
        ast.parse(src.text, filename=src.path)
    except SyntaxError as exc:
        yield make_finding(syntax_error.rule, src, exc.lineno or 1, f"Syntax error: {exc.msg}",
                           column=exc.offset or 1)


@rule("PY002", "bare-except", "Bare `except:` also catches KeyboardInterrupt and SystemExit.",
      category=Category.BUG, severity=Severity.WARNING, languages=PY, fixable=True)
def bare_except(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    for node in _all_nodes(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            line = src.line_text(node.lineno)
            fixed = re.sub(r"\bexcept\s*:", "except Exception:", line, count=1)
            yield make_finding(bare_except.rule, src, node.lineno,
                               "Bare `except:` catches every exception, including Ctrl-C.",
                               column=node.col_offset + 1,
                               suggestion="Catch a specific exception, or at least `except Exception:`.",
                               fix=Fix(node.lineno, fixed) if fixed != line else None)


@rule("PY003", "mutable-default-argument",
      "Mutable default argument is shared between calls.",
      category=Category.BUG, severity=Severity.ERROR, languages=PY)
def mutable_default(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    mutable_calls = {"list", "dict", "set", "defaultdict", "OrderedDict", "deque", "bytearray"}
    for node in _all_nodes(tree):
        if not isinstance(node, FUNC_TYPES):
            continue
        defaults = list(node.args.defaults) + [d for d in node.args.kw_defaults if d is not None]
        for d in defaults:
            is_mutable = isinstance(d, (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp,
                                        ast.SetComp))
            if isinstance(d, ast.Call) and _name(d.func).split(".")[-1] in mutable_calls:
                is_mutable = True
            if is_mutable:
                yield make_finding(mutable_default.rule, src, d.lineno,
                                   f"Mutable default in `{node.name}()` is created once and shared "
                                   "across every call.",
                                   column=d.col_offset + 1,
                                   suggestion="Default to `None` and create the object inside the function.")


@rule("PY004", "compare-to-none", "Use `is None` / `is not None` instead of `==`/`!=`.",
      category=Category.BUG, severity=Severity.WARNING, languages=PY, fixable=True)
def compare_to_none(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    for node in _all_nodes(tree):
        if not isinstance(node, ast.Compare):
            continue
        for op, comp in zip(node.ops, node.comparators):
            if isinstance(comp, ast.Constant) and comp.value is None and isinstance(op, (ast.Eq, ast.NotEq)):
                bad, good = ("==", "is") if isinstance(op, ast.Eq) else ("!=", "is not")
                line = src.line_text(node.lineno)
                fixed = re.sub(rf"\s*{re.escape(bad)}\s*None\b", f" {good} None", line)
                yield make_finding(compare_to_none.rule, src, node.lineno,
                                   f"Comparison `{bad} None` can be fooled by a custom __eq__; use `{good} None`.",
                                   column=node.col_offset + 1,
                                   fix=Fix(node.lineno, fixed)
                                   if fixed != line and node.lineno == node.end_lineno else None)


@rule("PY005", "is-literal", "`is` compares identity, not value, for str/int/bytes literals.",
      category=Category.BUG, severity=Severity.ERROR, languages=PY, fixable=True)
def is_literal(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    for node in _all_nodes(tree):
        if not isinstance(node, ast.Compare):
            continue
        operands = [node.left, *node.comparators]
        for idx, op in enumerate(node.ops):
            if not isinstance(op, (ast.Is, ast.IsNot)):
                continue
            for side in (operands[idx], operands[idx + 1]):
                if (isinstance(side, ast.Constant) and side.value is not None
                        and not isinstance(side.value, bool) and side.value is not Ellipsis):
                    good = "==" if isinstance(op, ast.Is) else "!="
                    line = src.line_text(node.lineno)
                    pattern = r"\bis\s+not\b" if isinstance(op, ast.IsNot) else r"\bis\b(?!\s+not)"
                    fixed = re.sub(pattern, good, line, count=1)
                    yield make_finding(is_literal.rule, src, node.lineno,
                                       f"`{'is not' if good == '!=' else 'is'}` with a literal compares "
                                       f"object identity; use `{good}`.",
                                       column=node.col_offset + 1,
                                       fix=Fix(node.lineno, fixed) if node.lineno == node.end_lineno else None)
                    break


@rule("PY006", "duplicate-dict-key", "Dictionary literal repeats a key; the earlier value is lost.",
      category=Category.BUG, severity=Severity.ERROR, languages=PY)
def duplicate_dict_key(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    for node in _all_nodes(tree):
        if not isinstance(node, ast.Dict):
            continue
        seen: Dict[object, int] = {}
        for k in node.keys:
            if isinstance(k, ast.Constant):
                key = (type(k.value).__name__, k.value)
                if key in seen:
                    yield make_finding(duplicate_dict_key.rule, src, k.lineno,
                                       f"Duplicate key {k.value!r} (first defined on line {seen[key]}).",
                                       column=k.col_offset + 1)
                else:
                    seen[key] = k.lineno


@rule("PY007", "assert-on-tuple", "`assert (cond, msg)` is always true.",
      category=Category.BUG, severity=Severity.ERROR, languages=PY)
def assert_tuple(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    for node in _all_nodes(tree):
        if isinstance(node, ast.Assert) and isinstance(node.test, ast.Tuple) and node.test.elts:
            yield make_finding(assert_tuple.rule, src, node.lineno,
                               "Asserting a non-empty tuple always passes.",
                               suggestion="Write `assert condition, \"message\"` without parentheses.")


@rule("PY008", "redefined-function", "Function or class is defined twice in the same scope.",
      category=Category.BUG, severity=Severity.WARNING, languages=PY)
def redefined_function(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    for scope in _all_nodes(tree):
        body = getattr(scope, "body", None)
        if not isinstance(body, list):
            continue
        seen: Dict[str, int] = {}
        for stmt in body:
            if isinstance(stmt, (*FUNC_TYPES, ast.ClassDef)):
                decorated = {_name(d.func if isinstance(d, ast.Call) else d).split(".")[-1]
                             for d in stmt.decorator_list}
                # property setters / overloads / singledispatch legitimately redefine.
                if decorated & {"setter", "getter", "deleter", "overload", "register"}:
                    continue
                if stmt.name in seen:
                    yield make_finding(redefined_function.rule, src, stmt.lineno,
                                       f"`{stmt.name}` redefines the definition on line {seen[stmt.name]}.",
                                       column=stmt.col_offset + 1)
                seen[stmt.name] = stmt.lineno


@rule("PY009", "open-without-with", "File opened without a context manager may never be closed.",
      category=Category.BUG, severity=Severity.WARNING, languages=PY)
def open_without_with(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    managed: Set[int] = set()
    for node in _all_nodes(tree):
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                managed.add(id(item.context_expr))
        # open(...).read() style one-liners are still leaky but extremely common;
        # flag only assignments, which are the cases that genuinely leak handles.
    for node in _all_nodes(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            call = node.value
            if _name(call.func) in ("open", "io.open") and id(call) not in managed:
                yield make_finding(open_without_with.rule, src, node.lineno,
                                   "File handle assigned without `with`; it leaks if an exception occurs.",
                                   column=node.col_offset + 1,
                                   suggestion="Use `with open(...) as f:`.")


@rule("PY010", "debugger-left-in", "Debugger breakpoint left in code.",
      category=Category.BUG, severity=Severity.ERROR, languages=PY, fixable=True)
def debugger_left_in(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    targets = {"breakpoint", "pdb.set_trace", "ipdb.set_trace", "pudb.set_trace"}
    # Statements that are the only thing in their block can't simply be deleted.
    sole: Set[int] = set()
    for parent in _all_nodes(tree):
        for field_name in ("body", "orelse", "finalbody"):
            body = getattr(parent, field_name, None)
            if isinstance(body, list) and len(body) == 1:
                sole.add(id(body[0]))
    for node in _all_nodes(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            if _name(node.value.func) in targets:
                line = src.line_text(node.lineno)
                fix = None
                # Only auto-fix if the call is alone on its line.
                if line.strip().rstrip(";").endswith(")") and line.strip().startswith(_name(node.value.func)):
                    indent = line[: len(line) - len(line.lstrip())]
                    fix = Fix(node.lineno, indent + "pass") if id(node) in sole else Fix(node.lineno, None)
                yield make_finding(debugger_left_in.rule, src, node.lineno,
                                   f"`{_name(node.value.func)}()` will pause execution in production.",
                                   column=node.col_offset + 1, fix=fix)


@rule("PY011", "swallowed-exception", "Exception is caught and silently ignored.",
      category=Category.BUG, severity=Severity.WARNING, languages=PY)
def swallowed_exception(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    for node in _all_nodes(tree):
        if isinstance(node, ast.ExceptHandler) and len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            if node.type is None or _name(node.type) in ("Exception", "BaseException"):
                yield make_finding(swallowed_exception.rule, src, node.lineno,
                                   "Broad exception silently swallowed with `pass`.",
                                   column=node.col_offset + 1,
                                   suggestion="Log it, narrow the exception type, or use contextlib.suppress(...) "
                                              "to make the intent explicit.")


@rule("PY012", "fstring-without-placeholders", "f-string has no placeholders.",
      category=Category.STYLE, severity=Severity.INFO, languages=PY, fixable=True)
def fstring_no_placeholder(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    # f-strings nested in format specs are JoinedStr too; skip those.
    nested: Set[int] = set()
    for node in _all_nodes(tree):
        if isinstance(node, ast.FormattedValue) and node.format_spec is not None:
            nested.add(id(node.format_spec))
    for node in _all_nodes(tree):
        if isinstance(node, ast.JoinedStr) and id(node) not in nested:
            if not any(isinstance(v, ast.FormattedValue) for v in node.values):
                line = src.line_text(node.lineno)
                fix = None
                if node.lineno == node.end_lineno:
                    seg = line[node.col_offset:node.end_col_offset]
                    m = re.match(r"([rRbB]?)[fF]([rR]?)(['\"])", seg)
                    if m:
                        prefix = m.group(1) + m.group(2)
                        new_seg = prefix + seg[m.end() - 1:]
                        fix = Fix(node.lineno, line[:node.col_offset] + new_seg + line[node.end_col_offset:])
                yield make_finding(fstring_no_placeholder.rule, src, node.lineno,
                                   "f-string without any `{}` placeholders; drop the `f` prefix.",
                                   column=node.col_offset + 1, fix=fix)


# --------------------------------------------------------------------------
# Maintainability
# --------------------------------------------------------------------------


@rule("PY020", "unused-import", "Imported name is never used.",
      category=Category.MAINTAINABILITY, severity=Severity.WARNING, languages=PY, fixable=True)
def unused_import(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree or src.path.endswith("__init__.py"):
        return  # __init__ files re-export by importing
    used: Set[str] = set()
    for node in _all_nodes(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
        elif isinstance(node, ast.Attribute):
            root = node
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name):
                used.add(root.id)
    # Names listed in __all__ or referenced in string annotations count as used.
    for node in _all_nodes(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            used.update(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", node.value)
                        if len(node.value) < 200 else ())
    for node in _all_nodes(tree):
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            continue
        for alias in node.names:
            if alias.name == "*":
                continue
            bound = alias.asname or alias.name.split(".")[0]
            # `import x as x` / `from y import x as x` is the explicit re-export idiom.
            if alias.asname and alias.asname == alias.name.split(".")[-1] and isinstance(node, ast.ImportFrom):
                continue
            if bound not in used:
                line = src.line_text(node.lineno)
                fix = Fix(node.lineno, None) if (len(node.names) == 1 and node.lineno == node.end_lineno
                                                 and line.strip().startswith(("import ", "from "))) else None
                yield make_finding(unused_import.rule, src, node.lineno,
                                   f"`{alias.asname or alias.name}` is imported but never used.",
                                   column=node.col_offset + 1, fix=fix)


@rule("PY021", "unused-variable", "Local variable is assigned but never read.",
      category=Category.MAINTAINABILITY, severity=Severity.WARNING, languages=PY)
def unused_variable(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    for func in _all_nodes(tree):
        if not isinstance(func, FUNC_TYPES):
            continue
        stored: Dict[str, ast.Name] = {}
        loaded: Set[str] = set()
        declared: Set[str] = set()
        uses_locals = False
        for node in ast.walk(func):  # includes nested scopes: closures may read our locals
            if isinstance(node, ast.Name):
                if isinstance(node.ctx, ast.Load):
                    loaded.add(node.id)
                    if node.id in ("locals", "vars"):
                        uses_locals = True
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                declared.update(node.names)
        if uses_locals:
            continue
        for node in _walk_scope(func):
            # Only simple `name = value` assignments; unpacking targets are often intentionally unused.
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets:
                    if isinstance(t, ast.Name) and t.id not in stored:
                        stored[t.id] = t
        for name, node in stored.items():
            if name.startswith("_") or name in loaded or name in declared:
                continue
            yield make_finding(unused_variable.rule, src, node.lineno,
                               f"Local variable `{name}` is assigned but never used.",
                               column=node.col_offset + 1)


@rule("PY022", "unreachable-code", "Statement can never execute.",
      category=Category.MAINTAINABILITY, severity=Severity.WARNING, languages=PY)
def unreachable_code(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    terminators = (ast.Return, ast.Raise, ast.Continue, ast.Break)
    for node in _all_nodes(tree):
        for field in ("body", "orelse", "finalbody"):
            body = getattr(node, field, None)
            if not isinstance(body, list):
                continue
            for i, stmt in enumerate(body[:-1]):
                if isinstance(stmt, terminators):
                    nxt = body[i + 1]
                    yield make_finding(unreachable_code.rule, src, nxt.lineno,
                                       f"Unreachable: follows `{type(stmt).__name__.lower()}` on line {stmt.lineno}.",
                                       column=nxt.col_offset + 1)
                    break


_BUILTINS = {n for n in dir(builtins) if not n.startswith("_")} - {
    "copyright", "credits", "license", "exit", "quit", "help",
}


@rule("PY023", "shadowed-builtin", "Name shadows a Python builtin.",
      category=Category.MAINTAINABILITY, severity=Severity.WARNING, languages=PY)
def shadowed_builtin(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    reported: Set[tuple] = set()

    def report(name: str, node: ast.AST, what: str):
        key = (name, node.lineno)
        if name in _BUILTINS and key not in reported:
            reported.add(key)
            return make_finding(shadowed_builtin.rule, src, node.lineno,
                                f"{what} `{name}` shadows the builtin `{name}()`.",
                                column=getattr(node, "col_offset", 0) + 1)
        return None

    # Class attributes / dataclass fields (e.g. `id: str`) don't shadow anything.
    class_attrs: Set[int] = set()
    for cls in _all_nodes(tree):
        if isinstance(cls, ast.ClassDef):
            for stmt in cls.body:
                targets = stmt.targets if isinstance(stmt, ast.Assign) else (
                    [stmt.target] if isinstance(stmt, ast.AnnAssign) else [])
                class_attrs.update(id(t) for t in targets)
    for node in _all_nodes(tree):
        f = None
        if id(node) in class_attrs:
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            f = report(node.id, node, "Variable")
        elif isinstance(node, ast.arg):
            f = report(node.arg, node, "Argument")
        if f:
            yield f
    if isinstance(tree, ast.Module):
        for stmt in tree.body:
            if isinstance(stmt, (*FUNC_TYPES, ast.ClassDef)):
                f = report(stmt.name, stmt, "Definition")
                if f:
                    yield f


_BRANCH_NODES = (ast.If, ast.IfExp, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler,
                 ast.Assert, ast.comprehension) + ((ast.match_case,) if hasattr(ast, "match_case") else ())


def _complexity(func: ast.AST) -> int:
    """McCabe-style cyclomatic complexity of a single function body."""
    score = 1
    for node in _walk_scope(func):
        if isinstance(node, _BRANCH_NODES):
            score += 1
        elif isinstance(node, ast.BoolOp):
            score += len(node.values) - 1
    return score


@rule("PY024", "high-complexity", "Function's cyclomatic complexity exceeds the limit.",
      category=Category.MAINTAINABILITY, severity=Severity.WARNING, languages=PY)
def high_complexity(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    for node in _all_nodes(tree):
        if isinstance(node, FUNC_TYPES):
            c = _complexity(node)
            if c > ctx.max_complexity:
                yield make_finding(high_complexity.rule, src, node.lineno,
                                   f"`{node.name}()` has cyclomatic complexity {c} (limit {ctx.max_complexity}).",
                                   column=node.col_offset + 1,
                                   suggestion="Split it into smaller helpers or use early returns / lookup tables.")


@rule("PY025", "too-many-arguments", "Function takes too many parameters.",
      category=Category.MAINTAINABILITY, severity=Severity.INFO, languages=PY)
def too_many_args(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    for node in _all_nodes(tree):
        if isinstance(node, FUNC_TYPES):
            a = node.args
            names = [x.arg for x in (*a.posonlyargs, *a.args, *a.kwonlyargs)]
            names = [n for n in names if n not in ("self", "cls")]
            if len(names) > ctx.max_arguments:
                yield make_finding(too_many_args.rule, src, node.lineno,
                                   f"`{node.name}()` takes {len(names)} parameters (limit {ctx.max_arguments}).",
                                   column=node.col_offset + 1,
                                   suggestion="Group related parameters into a dataclass or config object.")


@rule("PY026", "function-too-long", "Function body is longer than the configured limit.",
      category=Category.MAINTAINABILITY, severity=Severity.INFO, languages=PY)
def function_too_long(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    for node in _all_nodes(tree):
        if isinstance(node, FUNC_TYPES) and node.end_lineno:
            length = node.end_lineno - node.lineno + 1
            if length > ctx.max_function_length:
                yield make_finding(function_too_long.rule, src, node.lineno,
                                   f"`{node.name}()` is {length} lines long (limit {ctx.max_function_length}).",
                                   column=node.col_offset + 1)


# --------------------------------------------------------------------------
# Performance
# --------------------------------------------------------------------------


@rule("PY030", "string-concat-in-loop", "Building a string with `+=` inside a loop is quadratic.",
      category=Category.PERFORMANCE, severity=Severity.WARNING, languages=PY)
def string_concat_in_loop(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    for scope in _all_nodes(tree):
        if not isinstance(scope, (ast.Module, *FUNC_TYPES)):
            continue
        str_vars: Set[str] = set()
        for node in _walk_scope(scope):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                v = node.value
                if (isinstance(v, ast.Constant) and isinstance(v.value, str)) or isinstance(v, ast.JoinedStr):
                    str_vars.add(node.targets[0].id)
        if not str_vars:
            continue
        for loop in _walk_scope(scope):
            if not isinstance(loop, LOOP_TYPES):
                continue
            for node in _walk_scope(loop):
                if (isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add)
                        and isinstance(node.target, ast.Name) and node.target.id in str_vars):
                    yield make_finding(string_concat_in_loop.rule, src, node.lineno,
                                       f"`{node.target.id} += ...` in a loop copies the whole string each time.",
                                       column=node.col_offset + 1,
                                       suggestion="Append pieces to a list and `''.join(parts)` after the loop.")
                    break  # one finding per loop


@rule("PY031", "range-len-loop", "`for i in range(len(x))` where `enumerate` is clearer and faster.",
      category=Category.STYLE, severity=Severity.INFO, languages=PY)
def range_len_loop(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    for node in _all_nodes(tree):
        if not (isinstance(node, ast.For) and isinstance(node.iter, ast.Call) and _name(node.iter.func) == "range"):
            continue
        args = node.iter.args
        if len(args) != 1 or not (isinstance(args[0], ast.Call) and _name(args[0].func) == "len"
                                  and len(args[0].args) == 1):
            continue
        seq = ast.unparse(args[0].args[0])
        if not isinstance(node.target, ast.Name):
            continue
        idx = node.target.id
        # Only suggest when the body actually indexes the sequence with the loop var.
        indexes = any(isinstance(n, ast.Subscript) and ast.unparse(n.value) == seq
                      and isinstance(n.slice, ast.Name) and n.slice.id == idx
                      for n in ast.walk(node))
        if indexes:
            yield make_finding(range_len_loop.rule, src, node.lineno,
                               f"Iterate with `for {idx}, item in enumerate({seq})` instead of indexing.",
                               column=node.col_offset + 1)


@rule("PY032", "unnecessary-list-in-any-all",
      "`any([...])`/`all([...])` builds the whole list and can't short-circuit.",
      category=Category.PERFORMANCE, severity=Severity.INFO, languages=PY, fixable=True)
def list_in_any_all(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    for node in _all_nodes(tree):
        if (isinstance(node, ast.Call) and _name(node.func) in ("any", "all", "sum", "min", "max")
                and len(node.args) == 1 and isinstance(node.args[0], ast.ListComp) and not node.keywords):
            comp = node.args[0]
            line = src.line_text(node.lineno)
            fix = None
            if comp.lineno == comp.end_lineno:
                inner = line[comp.col_offset + 1:comp.end_col_offset - 1]
                fixed = line[:comp.col_offset] + inner + line[comp.end_col_offset:]
                fix = Fix(comp.lineno, fixed)
            yield make_finding(list_in_any_all.rule, src, node.lineno,
                               f"Pass a generator to `{_name(node.func)}()` instead of a list comprehension.",
                               column=node.col_offset + 1, fix=fix)


@rule("PY033", "membership-on-keys", "`x in d.keys()` / `x in list(...)` is slower than `x in d`.",
      category=Category.PERFORMANCE, severity=Severity.INFO, languages=PY)
def membership_on_keys(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    for node in _all_nodes(tree):
        if not isinstance(node, ast.Compare):
            continue
        for op, comp in zip(node.ops, node.comparators):
            if not isinstance(op, (ast.In, ast.NotIn)) or not isinstance(comp, ast.Call):
                continue
            fn = comp.func
            if isinstance(fn, ast.Attribute) and fn.attr == "keys" and not comp.args:
                yield make_finding(membership_on_keys.rule, src, node.lineno,
                                   f"Use `in {ast.unparse(fn.value)}` directly; `.keys()` is redundant.",
                                   column=node.col_offset + 1)
            elif _name(fn) == "list" and len(comp.args) == 1:
                yield make_finding(membership_on_keys.rule, src, node.lineno,
                                   "`in list(...)` copies the iterable and does a linear scan.",
                                   column=node.col_offset + 1,
                                   suggestion="Test membership on the original container (or a set).")


@rule("PY034", "sorted-for-min-max", "`sorted(x)[0]` / `sorted(x)[-1]` is O(n log n); use min()/max().",
      category=Category.PERFORMANCE, severity=Severity.INFO, languages=PY)
def sorted_for_min_max(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    for node in _all_nodes(tree):
        if (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Call)
                and _name(node.value.func) == "sorted" and isinstance(node.slice, (ast.Constant, ast.UnaryOp))):
            try:
                idx = ast.literal_eval(node.slice)
            except ValueError:
                continue
            reverse = any(k.arg == "reverse" for k in node.value.keywords)
            if idx in (0, -1) and not reverse:
                fn = "min" if idx == 0 else "max"
                yield make_finding(sorted_for_min_max.rule, src, node.lineno,
                                   f"Use `{fn}(...)` instead of sorting the whole sequence.",
                                   column=node.col_offset + 1)


@rule("PY035", "mutate-while-iterating",
      "Collection is modified while it is being iterated over.",
      category=Category.BUG, severity=Severity.ERROR, languages=PY)
def mutate_while_iterating(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    mutators = {"append", "extend", "insert", "remove", "pop", "clear", "add", "discard", "update"}
    for loop in _all_nodes(tree):
        if not isinstance(loop, (ast.For, ast.AsyncFor)) or not isinstance(loop.iter, ast.Name):
            continue
        seq = loop.iter.id
        for node in ast.walk(loop):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in mutators and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == seq):
                yield make_finding(mutate_while_iterating.rule, src, node.lineno,
                                   f"`{seq}.{node.func.attr}()` while iterating over `{seq}` skips or repeats "
                                   "elements (or loops forever).",
                                   column=node.col_offset + 1,
                                   suggestion=f"Iterate over a copy (`for x in list({seq}):`) "
                                              "or build a new collection.")
                break


# --------------------------------------------------------------------------
# Security
# --------------------------------------------------------------------------


@rule("PY040", "eval-exec", "`eval`/`exec` on dynamic input enables code injection.",
      category=Category.SECURITY, severity=Severity.WARNING, languages=PY)
def eval_exec(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    for node in _all_nodes(tree):
        if isinstance(node, ast.Call) and _name(node.func) in ("eval", "exec"):
            if node.args and isinstance(node.args[0], ast.Constant):
                continue
            yield make_finding(eval_exec.rule, src, node.lineno,
                               f"`{_name(node.func)}()` on a non-constant expression.",
                               column=node.col_offset + 1,
                               suggestion="Use ast.literal_eval, json.loads, or an explicit dispatch table.")


@rule("PY041", "subprocess-shell-true", "`shell=True` passes the command through the shell.",
      category=Category.SECURITY, severity=Severity.WARNING, languages=PY)
def subprocess_shell(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    for node in _all_nodes(tree):
        if isinstance(node, ast.Call) and _name(node.func).startswith(("subprocess.", "os.system", "os.popen")):
            if _name(node.func) in ("os.system", "os.popen"):
                yield make_finding(subprocess_shell.rule, src, node.lineno,
                                   f"`{_name(node.func)}()` runs through the shell; prefer subprocess.run([...]).",
                                   column=node.col_offset + 1)
                continue
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    first = node.args[0] if node.args else None
                    if isinstance(first, ast.Constant):
                        continue  # constant command string: no injection vector
                    yield make_finding(subprocess_shell.rule, src, node.lineno,
                                       "`shell=True` with a dynamic command allows shell injection.",
                                       column=node.col_offset + 1,
                                       suggestion="Pass an argument list and drop shell=True.")


@rule("PY042", "requests-without-timeout", "HTTP request without a timeout can hang forever.",
      category=Category.BUG, severity=Severity.WARNING, languages=PY)
def requests_without_timeout(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    methods = {"get", "post", "put", "patch", "delete", "head", "options", "request"}
    for node in _all_nodes(tree):
        if isinstance(node, ast.Call):
            name = _name(node.func)
            parts = name.split(".")
            if len(parts) == 2 and parts[0] in ("requests", "httpx") and parts[1] in methods:
                if not any(k.arg == "timeout" for k in node.keywords) and not any(
                        k.arg is None for k in node.keywords):
                    yield make_finding(requests_without_timeout.rule, src, node.lineno,
                                       f"`{name}()` has no timeout.",
                                       column=node.col_offset + 1,
                                       suggestion="Pass `timeout=` (e.g. `timeout=10`).")


# --------------------------------------------------------------------------
# Style
# --------------------------------------------------------------------------


@rule("PY050", "compare-to-bool", "Comparing to True/False with `==` is redundant.",
      category=Category.STYLE, severity=Severity.INFO, languages=PY)
def compare_to_bool(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    for node in _all_nodes(tree):
        if isinstance(node, ast.Compare):
            for op, comp in zip(node.ops, node.comparators):
                if (isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(comp, ast.Constant)
                        and isinstance(comp.value, bool)):
                    yield make_finding(compare_to_bool.rule, src, node.lineno,
                                       f"`== {comp.value}` is redundant; use the expression's truthiness directly.",
                                       column=node.col_offset + 1)


@rule("PY051", "len-as-condition", "`len(x) == 0` / `len(x) > 0` instead of truthiness.",
      category=Category.STYLE, severity=Severity.INFO, languages=PY)
def len_as_condition(src: SourceFile, ctx: RuleContext):
    tree = parse(src)
    if not tree:
        return
    for node in _all_nodes(tree):
        if (isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.left, ast.Call)
                and _name(node.left.func) == "len" and isinstance(node.comparators[0], ast.Constant)
                and node.comparators[0].value == 0
                and isinstance(node.ops[0], (ast.Eq, ast.NotEq, ast.Gt))):
            arg = ast.unparse(node.left.args[0]) if node.left.args else "x"
            better = f"not {arg}" if isinstance(node.ops[0], ast.Eq) else arg
            yield make_finding(len_as_condition.rule, src, node.lineno,
                               f"Use `{better}` instead of comparing len() to 0.",
                               column=node.col_offset + 1)


@rule("PY052", "quote-style", "String quotes don't match the project's preferred quote style.",
      category=Category.STYLE, severity=Severity.INFO, languages=PY)
def py_quote_style(src: SourceFile, ctx: RuleContext):
    if ctx.quote_style not in ("single", "double"):
        return
    want, other = ("'", '"') if ctx.quote_style == "single" else ('"', "'")
    import io
    import tokenize
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(src.text).readline))
    except (tokenize.TokenError, SyntaxError, IndentationError):
        return
    for tok in tokens:
        if tok.type != tokenize.STRING:
            continue
        body = tok.string.lstrip("rRbBuUfF")
        if body.startswith(other * 3) or body.startswith(want * 3):
            continue  # docstrings / triple-quoted: leave alone
        if body.startswith(other) and want not in body[1:-1]:
            yield make_finding(py_quote_style.rule, src, tok.start[0],
                               f"Use {ctx.quote_style} quotes for consistency with the project style.",
                               column=tok.start[1] + 1)

