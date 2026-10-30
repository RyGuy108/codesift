"""Discovers files, runs rules, and post-processes findings."""

from __future__ import annotations

import json
import os
import re
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set

from . import gitutil
from .config import DEFAULT_EXCLUDES, Config, detect_language, glob_match
from .models import Finding, SourceFile
from .rules import all_rules
from .rules import javascript as js_rules
from .rules import python as py_rules

MAX_FILE_BYTES = 1_000_000

_SUPPRESS_RE = re.compile(
    r"codesift:\s*(?:ignore|disable)(?P<scope>-next-line|-file)?(?:\[(?P<ids>[^\]]*)\])?", re.I
)


@dataclass
class RunResult:
    findings: List[Finding]
    files_scanned: int
    suppressed: int = 0
    baselined: int = 0
    filtered_by_diff: int = 0
    duration: float = 0.0
    errors: List[str] = field(default_factory=list)
    sources: Dict[str, SourceFile] = field(default_factory=dict)

    def counts(self) -> Counter:
        return Counter(f.severity.label for f in self.findings)


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------


def discover(cfg: Config, paths: Optional[Iterable[str]] = None) -> List[str]:
    """Return repo-relative paths of files to analyze."""
    root = cfg.root
    candidates: List[str] = []
    explicit: List[str] = []  # paths named on the command line win over exclude patterns
    git_files: Optional[List[str]] = None
    if gitutil.repo_root(root):
        try:
            git_files = gitutil.list_files(root)  # respects .gitignore
        except gitutil.GitError:
            git_files = None
    if paths:
        for p in paths:
            ap = os.path.abspath(p)
            rel_arg = os.path.relpath(ap, root).replace(os.sep, "/")
            if os.path.isdir(ap):
                prefix = "" if rel_arg == "." else rel_arg.rstrip("/") + "/"
                if git_files is not None:
                    candidates.extend(f for f in git_files if f.startswith(prefix))
                else:
                    candidates.extend(_walk(root, ap))
                if prefix:
                    explicit.append(prefix)
            elif os.path.isfile(ap):
                candidates.append(rel_arg)
                explicit.append(rel_arg)
    else:
        candidates = git_files if git_files is not None else _walk(root, root)

    out = []
    for rel in candidates:
        rel = rel.replace(os.sep, "/")
        if detect_language(rel) is None:
            continue
        if cfg.is_excluded(rel) and not _explicitly_requested(rel, explicit):
            continue
        out.append(rel)
    return sorted(set(out))


def _explicitly_requested(rel: str, explicit: List[str]) -> bool:
    """A path named on the command line overrides user excludes for itself, but
    built-in excludes (node_modules, .venv, ...) inside a named directory still apply."""
    for e in explicit:
        if e == rel:
            return True
        if e.endswith("/") and rel.startswith(e):
            return not any(glob_match(rel[len(e):], p) for p in DEFAULT_EXCLUDES)
    return False


def _walk(root: str, start: str) -> List[str]:
    skip = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox"}
    found = []
    for dirpath, dirnames, filenames in os.walk(start):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for name in filenames:
            found.append(os.path.relpath(os.path.join(dirpath, name), root).replace(os.sep, "/"))
    return found


def load_source(root: str, rel: str) -> Optional[SourceFile]:
    abs_path = os.path.join(root, rel)
    try:
        if os.path.getsize(abs_path) > MAX_FILE_BYTES:
            return None
        with open(abs_path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return None
    if b"\0" in raw[:8192]:
        return None  # binary
    text = raw.decode("utf-8", errors="replace")
    return SourceFile(path=rel, abs_path=abs_path, text=text, language=detect_language(rel) or "text")


# --------------------------------------------------------------------------
# Suppressions
# --------------------------------------------------------------------------


def _parse_ids(raw: Optional[str]) -> Optional[Set[str]]:
    if not raw:
        return None  # all rules
    return {x.strip() for x in raw.split(",") if x.strip()}


def _suppression_map(src: SourceFile):
    """(file_level_ids, {line: ids}). ``None`` ids means every rule."""
    file_level: List[Optional[Set[str]]] = []
    by_line: Dict[int, List[Optional[Set[str]]]] = {}
    if "codesift:" not in src.text:
        return file_level, by_line
    for i, line in enumerate(src.lines, 1):
        for m in _SUPPRESS_RE.finditer(line):
            ids = _parse_ids(m.group("ids"))
            scope = (m.group("scope") or "").lower()
            if scope == "-file":
                file_level.append(ids)
            elif scope == "-next-line":
                by_line.setdefault(i + 1, []).append(ids)
            else:
                by_line.setdefault(i, []).append(ids)
    return file_level, by_line


def _matches(ids: Optional[Set[str]], f: Finding, name: str) -> bool:
    return ids is None or f.rule_id in ids or name in ids


# --------------------------------------------------------------------------
# Baseline
# --------------------------------------------------------------------------


def load_baseline(path: str) -> Counter:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return Counter(data.get("findings", {}))


def write_baseline(path: str, findings: List[Finding]) -> None:
    counts = Counter(f.fingerprint() for f in findings)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"version": 1, "tool": "codesift", "findings": dict(sorted(counts.items()))}, fh, indent=2)
        fh.write("\n")


# --------------------------------------------------------------------------
# Run
# --------------------------------------------------------------------------


def analyze_file(src: SourceFile, cfg: Config) -> List[Finding]:
    rules = all_rules()
    ctx = cfg.context_for(src.path)
    file_level, by_line = _suppression_map(src)
    findings: List[Finding] = []
    seen = set()
    for r in rules.values():
        if not r.applies_to(src.language) or not cfg.rule_enabled(r.id, r.name, src.path):
            continue
        if any(_matches(ids, Finding(r.id, "", src.path, 0), r.name) for ids in file_level):
            continue
        try:
            produced = list(r.check(src, ctx) or [])
        except Exception as exc:  # a buggy rule must never kill the run
            produced = []
            findings.append(Finding("INTERNAL", f"Rule {r.id} crashed: {exc!r}", src.path, 1))
        for f in produced:
            key = (f.rule_id, f.line, f.column)
            if key in seen:
                continue
            seen.add(key)
            f.severity = cfg.severity_for(r.id, r.name, f.severity)
            if any(_matches(ids, f, r.name) for ids in by_line.get(f.line, [])):
                f.rule_id = "__suppressed__:" + f.rule_id
            findings.append(f)
    return findings


def run(cfg: Config, paths: Optional[Iterable[str]] = None, *, diff_base: Optional[str] = None,
        staged: bool = False, use_baseline: bool = True, jobs: int = 0) -> RunResult:
    start = time.perf_counter()
    root = cfg.root
    files = discover(cfg, paths)

    changed: Optional[Dict[str, Set[int]]] = None
    if diff_base or staged:
        changed = gitutil.changed_lines(root, diff_base, staged=staged)
        files = [f for f in files if f in changed]

    sources = [s for s in (load_source(root, f) for f in files) if s is not None]
    workers = jobs or min(8, (os.cpu_count() or 2))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        per_file = list(pool.map(lambda s: analyze_file(s, cfg), sources))
    py_rules.clear_cache()
    js_rules.clear_cache()

    result = RunResult(findings=[], files_scanned=len(sources), sources={s.path: s for s in sources})
    all_findings: List[Finding] = []
    for fs in per_file:
        for f in fs:
            if f.rule_id.startswith("__suppressed__:"):
                result.suppressed += 1
                continue
            if f.rule_id == "INTERNAL":
                result.errors.append(f"{f.path}: {f.message}")
                continue
            all_findings.append(f)

    if changed is not None:
        kept = []
        for f in all_findings:
            lines = changed.get(f.path, set())
            span = set(range(f.line, (f.end_line or f.line) + 1))
            if -1 in lines or lines & span:
                kept.append(f)
            else:
                result.filtered_by_diff += 1
        all_findings = kept

    baseline_path = cfg.baseline and os.path.join(root, cfg.baseline)
    if use_baseline and baseline_path and os.path.isfile(baseline_path):
        remaining = load_baseline(baseline_path)
        kept = []
        for f in all_findings:
            fp = f.fingerprint()
            if remaining.get(fp, 0) > 0:
                remaining[fp] -= 1
                result.baselined += 1
            else:
                kept.append(f)
        all_findings = kept

    result.findings = sorted(all_findings, key=Finding.sort_key)
    result.duration = time.perf_counter() - start
    return result
