"""Command-line interface.

    codesift [check] [PATHS...]   analyze (default command)
    codesift ci                   GitHub Actions mode: annotations, summary, SARIF, PR comment
    codesift init                 infer the repo's style and write .codesift.toml (+ workflow / hook)
    codesift baseline             record current findings so only new ones are reported
    codesift rules                list available rules
    codesift install-hook         install a git pre-commit hook
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
from typing import List, Optional

from . import __version__, engine, gitutil
from .config import Config, load_config
from .fixer import apply_fixes, unified_diff
from .models import Severity
from .reporters import FORMATTERS, format_markdown, format_sarif, format_text, summary_line
from .rules import all_rules

COMMANDS = ("check", "ci", "init", "baseline", "rules", "install-hook")


# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--root", default=None, help="project root (default: git root or cwd)")
    p.add_argument("--config", help="path to a codesift TOML config")
    p.add_argument("--select", action="append", default=[], metavar="RULES",
                   help="only run these rule IDs/prefixes/names (comma separated, repeatable)")
    p.add_argument("--disable", action="append", default=[], metavar="RULES",
                   help="skip these rule IDs/prefixes/names")
    p.add_argument("--fail-on", choices=["error", "warning", "info", "never"],
                   help="lowest severity that makes the exit code non-zero (default: from config, else error)")
    p.add_argument("--no-baseline", action="store_true", help="ignore the baseline file")
    p.add_argument("-j", "--jobs", type=int, default=0, help="worker threads (default: auto)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="codesift", description="Find bugs, performance problems and "
                                     "style drift. Runs locally, as a pre-commit hook, or in GitHub Actions.")
    parser.add_argument("--version", action="version", version=f"codesift {__version__}")
    sub = parser.add_subparsers(dest="command")

    check = sub.add_parser("check", help="analyze files (default)")
    _common(check)
    check.add_argument("paths", nargs="*", help="files or directories (default: whole repo)")
    check.add_argument("-f", "--format", choices=sorted(FORMATTERS), default="text")
    check.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    check.add_argument("--sarif", metavar="FILE", help="additionally write a SARIF report")
    check.add_argument("--fix", action="store_true", help="apply safe automatic fixes in place")
    check.add_argument("--fix-diff", action="store_true", help="print fixes as a unified diff without writing")
    scope = check.add_mutually_exclusive_group()
    scope.add_argument("--changed", nargs="?", const="HEAD", metavar="BASE",
                       help="only report issues on lines changed relative to BASE (default HEAD; e.g. origin/main)")
    scope.add_argument("--staged", action="store_true", help="only report issues on staged lines (pre-commit)")
    check.add_argument("--no-source", action="store_true", help="don't print source snippets")
    check.add_argument("-q", "--quiet", action="store_true", help="only print the summary line")
    check.add_argument("--statistics", action="store_true", help="print a per-rule count table")

    ci = sub.add_parser("ci", help="GitHub Actions mode")
    _common(ci)
    ci.add_argument("--scope", choices=["auto", "changed", "all"], default="auto",
                    help="auto = changed lines on pull requests, whole repo otherwise")
    ci.add_argument("--base", help="base ref for --scope changed (default: origin/$GITHUB_BASE_REF)")
    ci.add_argument("--sarif", metavar="FILE", default="codesift.sarif", help="SARIF output path ('' to skip)")
    ci.add_argument("--comment", choices=["always", "on-issues", "never"], default="on-issues",
                    help="sticky PR comment behaviour")
    ci.add_argument("--suggest", action="store_true",
                    help="post one-click ```suggestion review comments for auto-fixable issues")
    ci.add_argument("--max-annotations", type=int, default=200)

    init = sub.add_parser("init", help="infer project style and write config")
    init.add_argument("--root", default=None)
    init.add_argument("--force", action="store_true", help="overwrite an existing config")
    init.add_argument("--github", action="store_true", help="also write .github/workflows/codesift.yml")
    init.add_argument("--hook", action="store_true", help="also install the git pre-commit hook")
    init.add_argument("--dry-run", action="store_true", help="print what would be written")

    base = sub.add_parser("baseline", help="record current findings as accepted")
    _common(base)
    base.add_argument("--file", help="baseline path (default: config 'baseline' or .codesift-baseline.json)")

    rules = sub.add_parser("rules", help="list rules")
    rules.add_argument("--markdown", action="store_true")

    hook = sub.add_parser("install-hook", help="install git pre-commit hook")
    hook.add_argument("--root", default=None)
    hook.add_argument("--force", action="store_true")
    return parser


def _split(values: List[str]) -> List[str]:
    return [x.strip() for v in values for x in v.split(",") if x.strip()]


def _resolve_root(arg: Optional[str]) -> str:
    if arg:
        return os.path.abspath(arg)
    return gitutil.repo_root(os.getcwd()) or os.getcwd()


def _load(args) -> Config:
    cfg = load_config(_resolve_root(args.root), args.config)
    cfg.select += _split(args.select)
    cfg.disable += _split(args.disable)
    if args.fail_on == "never":
        cfg.fail_on = None  # type: ignore[assignment]
    elif args.fail_on:
        cfg.fail_on = Severity.parse(args.fail_on)
    return cfg


def _exit_code(result: engine.RunResult, cfg: Config) -> int:
    if cfg.fail_on is None:
        return 0
    return 1 if any(f.severity >= cfg.fail_on for f in result.findings) else 0


def _write(path: Optional[str], text: str) -> None:
    if path:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
    else:
        sys.stdout.write(text + ("\n" if text and not text.endswith("\n") else ""))


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def cmd_check(args) -> int:
    cfg = _load(args)
    kwargs = dict(diff_base=args.changed, staged=args.staged, use_baseline=not args.no_baseline, jobs=args.jobs)
    try:
        result = engine.run(cfg, args.paths or None, **kwargs)
    except gitutil.GitError as exc:
        print(f"codesift: git error: {exc}", file=sys.stderr)
        return 2

    if args.fix or args.fix_diff:
        return _do_fix(cfg, args, result, kwargs)

    if args.sarif:
        _write(args.sarif, format_sarif(result))
    if args.quiet:
        print(summary_line(result))
    elif args.format == "text":
        _write(args.output, format_text(result, show_source=not args.no_source,
                                        color=False if args.output else None))
    elif args.format == "markdown":
        _write(args.output, format_markdown(result, fail_on=cfg.fail_on))
    else:
        _write(args.output, FORMATTERS[args.format](result))
    if args.statistics:
        _print_statistics(result)
    return _exit_code(result, cfg)


def _do_fix(cfg: Config, args, result: engine.RunResult, kwargs) -> int:
    total_applied = 0
    touched = set()
    # Several fixes can target the same line (e.g. whitespace + `== None`), so iterate.
    for _ in range(5):
        fixable = [f for f in result.findings if f.fix]
        if not fixable:
            break
        applied_this_pass = 0
        for path in sorted({f.path for f in fixable}):
            src = result.sources[path]
            new_text, applied = apply_fixes(src, [f for f in fixable if f.path == path])
            if not applied or new_text == src.text:
                continue
            if src.language == "python" and not _still_parses(src.text, new_text):
                print(f"codesift: skipped fixes for {path}: result would not parse.", file=sys.stderr)
                continue
            if args.fix_diff:
                sys.stdout.write(unified_diff(path, src.text, new_text))
            else:
                with open(src.abs_path, "w", encoding="utf-8", newline="") as fh:
                    fh.write(new_text)
            touched.add(path)
            applied_this_pass += applied
        total_applied += applied_this_pass
        if args.fix_diff or not applied_this_pass:
            break
        result = engine.run(cfg, [os.path.join(cfg.root, p) for p in sorted(touched)], **kwargs)

    if args.fix_diff:
        return 0
    final = engine.run(cfg, args.paths or None, **kwargs)
    print(f"Applied {total_applied} fix(es) to {len(touched)} file(s).", file=sys.stderr)
    if final.findings and not args.quiet:
        print(format_text(final, show_source=not args.no_source))
    else:
        print(summary_line(final))
    return _exit_code(final, cfg)


def _still_parses(old: str, new: str) -> bool:
    """Safety net: never let an auto-fix turn a valid Python file into an invalid one."""
    import ast
    try:
        ast.parse(old)
    except SyntaxError:
        return True  # was already broken; nothing to protect
    try:
        ast.parse(new)
        return True
    except SyntaxError:
        return False


def _print_statistics(result: engine.RunResult) -> None:
    from collections import Counter
    rules = all_rules()
    counts = Counter(f.rule_id for f in result.findings)
    print()
    print(f"{'count':>6}  {'rule':<6} {'name':<32} category")
    for rid, n in counts.most_common():
        r = rules.get(rid)
        print(f"{n:>6}  {rid:<6} {r.name if r else '':<32} {r.category.value if r else ''}")


def cmd_ci(args) -> int:
    from . import github

    if os.environ.get("GITHUB_WORKSPACE") and not args.root:
        args.root = os.environ["GITHUB_WORKSPACE"]
    cfg = _load(args)
    gh = github.GitHubContext.from_env()
    is_pr = bool(gh and gh.pr_number) or os.environ.get("GITHUB_EVENT_NAME", "").startswith("pull_request")

    diff_base = None
    scope = args.scope if args.scope != "auto" else ("changed" if is_pr else "all")
    if scope == "changed":
        base_ref = args.base or (f"origin/{os.environ['GITHUB_BASE_REF']}"
                                 if os.environ.get("GITHUB_BASE_REF") else "HEAD~1")
        diff_base = base_ref
    try:
        result = engine.run(cfg, diff_base=diff_base, use_baseline=not args.no_baseline, jobs=args.jobs)
    except gitutil.GitError as exc:
        print(f"::warning title=codesift::Could not diff against {diff_base} ({exc}). "
              "Scanning the whole repository instead. Use `fetch-depth: 0` in actions/checkout.")
        result = engine.run(cfg, use_baseline=not args.no_baseline, jobs=args.jobs)
        scope = "all"

    # 1) Inline annotations on the PR "Files changed" tab.
    print(f"::group::codesift found {len(result.findings)} issue(s) [{scope} scope]")
    print(format_text(result, color=True))
    print("::endgroup::")
    from .reporters import format_github
    annotations = format_github(result, args.max_annotations)
    if annotations:
        print(annotations)

    # 2) SARIF for the Security → Code scanning tab.
    if args.sarif:
        _write(os.path.join(cfg.root, args.sarif), format_sarif(result))

    # 3) Job summary + sticky PR comment.
    link_base = gh.blob_base if gh else None
    md = format_markdown(result, link_base=link_base, fail_on=cfg.fail_on)
    github.write_step_summary(md)
    if gh and gh.pr_number and args.comment != "never":
        try:
            action = github.upsert_pr_comment(gh, md, clean=not result.findings,
                                              delete_when_clean=args.comment == "on-issues")
            print(f"codesift: PR comment {action}.")
        except Exception as exc:  # permissions on fork PRs, etc.
            print(f"::warning title=codesift::Could not update PR comment: {exc}. "
                  "Grant `pull-requests: write` to the workflow.")
        if args.suggest:
            try:
                n = github.post_suggestions(gh, result)
                print(f"codesift: posted {n} suggested fix(es).")
            except Exception as exc:
                print(f"::warning title=codesift::Could not post suggestions: {exc}")

    counts = result.counts()
    github.set_outputs(total=len(result.findings), errors=counts.get("error", 0),
                       warnings=counts.get("warning", 0), infos=counts.get("info", 0),
                       sarif=os.path.join(cfg.root, args.sarif) if args.sarif else "",
                       scope=scope)
    print(summary_line(result))
    return _exit_code(result, cfg)


WORKFLOW_TEMPLATE = """\
name: codesift

on:
  pull_request:
  push:
    branches: [main, master]

permissions:
  contents: read
  pull-requests: write     # sticky PR comment + suggested fixes
  security-events: write   # upload SARIF to the Code scanning tab

jobs:
  codesift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0       # needed to diff against the PR base
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install codesift
        run: pip install "git+https://github.com/codesift/codesift@v1"
      - name: Run codesift
        id: codesift
        run: codesift ci --suggest
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      - name: Upload SARIF
        if: always() && hashFiles('codesift.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: codesift.sarif
          category: codesift
"""

HOOK_MARKER = "# installed by codesift"


def cmd_init(args) -> int:
    from .style import infer, render_config

    root = _resolve_root(args.root)
    cfg = load_config(root)
    profiles = infer(cfg)
    for lang, p in profiles.items():
        print(f"Detected {lang} style from {p.files} file(s): indent={p.indent_style}/{p.indent_size}, "
              f"quotes={p.quote_style}, max line={p.max_line_length}")
        for k, v in p.evidence.items():
            print(f"    {k}: {v}")
    text = render_config(profiles)
    target = os.path.join(root, ".codesift.toml")
    if args.dry_run:
        print("\n# .codesift.toml\n" + text)
    elif os.path.exists(target) and not args.force:
        print(f"{target} already exists (use --force to overwrite).", file=sys.stderr)
    else:
        _write(target, text)
        print(f"Wrote {os.path.relpath(target)}")

    if args.github:
        wf = os.path.join(root, ".github", "workflows", "codesift.yml")
        if args.dry_run:
            print("\n# .github/workflows/codesift.yml\n" + WORKFLOW_TEMPLATE)
        elif os.path.exists(wf) and not args.force:
            print(f"{wf} already exists (use --force).", file=sys.stderr)
        else:
            _write(wf, WORKFLOW_TEMPLATE)
            print(f"Wrote {os.path.relpath(wf)}")
    if args.hook and not args.dry_run:
        _install_hook(root, args.force)
    return 0


def cmd_baseline(args) -> int:
    cfg = _load(args)
    path = args.file or cfg.baseline or ".codesift-baseline.json"
    result = engine.run(cfg, use_baseline=False, jobs=args.jobs)
    engine.write_baseline(os.path.join(cfg.root, path), result.findings)
    print(f"Baseline of {len(result.findings)} finding(s) written to {path}.")
    if not cfg.baseline:
        print(f'Add `baseline = "{path}"` to your [codesift] config to enable it.')
    return 0


def cmd_rules(args) -> int:
    rules = sorted(all_rules().values(), key=lambda r: r.id)
    if args.markdown:
        print("| ID | Name | Category | Default | Fix | Languages | Description |")
        print("|---|---|---|---|:-:|---|---|")
        for r in rules:
            langs = ", ".join(sorted(r.languages)) or "all"
            print(f"| `{r.id}` | {r.name} | {r.category.value} | {r.default_severity.label} | "
                  f"{'✓' if r.fixable else ''} | {langs} | {r.description} |")
        return 0
    for r in rules:
        langs = ",".join(sorted(r.languages)) or "all"
        fix = " (fixable)" if r.fixable else ""
        print(f"{r.id:<6} {r.name:<32} {r.default_severity.label:<8} {r.category.value:<16} [{langs}]{fix}")
        print(f"       {r.description}")
    return 0


def _install_hook(root: str, force: bool) -> int:
    git_dir = os.path.join(root, ".git")
    if not os.path.isdir(git_dir):
        print("Not a git repository (no .git directory).", file=sys.stderr)
        return 1
    hook = os.path.join(git_dir, "hooks", "pre-commit")
    if os.path.exists(hook) and not force:
        with open(hook, encoding="utf-8", errors="replace") as fh:
            if HOOK_MARKER not in fh.read():
                print(f"{hook} exists and wasn't created by codesift (use --force).", file=sys.stderr)
                return 1
    os.makedirs(os.path.dirname(hook), exist_ok=True)
    with open(hook, "w", encoding="utf-8") as fh:
        fh.write(f"""#!/bin/sh
{HOOK_MARKER}
# Checks only the lines you're committing. Bypass once with: git commit --no-verify
"{sys.executable}" -m codesift check --staged --no-source
status=$?
if [ $status -ne 0 ]; then
  echo ""
  echo "codesift: commit blocked. Run 'codesift check --fix' to auto-fix what it can."
fi
exit $status
""")
    os.chmod(hook, os.stat(hook).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"Installed pre-commit hook at {os.path.relpath(hook)}")
    return 0


def cmd_install_hook(args) -> int:
    return _install_hook(_resolve_root(args.root), args.force)


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or (argv[0] not in COMMANDS and argv[0] not in ("-h", "--help", "--version")):
        argv.insert(0, "check")
    args = build_parser().parse_args(argv)
    handlers = {"check": cmd_check, "ci": cmd_ci, "init": cmd_init, "baseline": cmd_baseline,
                "rules": cmd_rules, "install-hook": cmd_install_hook}
    try:
        return handlers[args.command](args)
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:  # e.g. `codesift rules | head`
        sys.stderr.close()
        return 0
    except (ValueError, RuntimeError) as exc:
        print(f"codesift: {exc}", file=sys.stderr)
        return 2
