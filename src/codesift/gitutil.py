"""Thin wrappers around the git CLI."""

from __future__ import annotations

import os
import re
import subprocess
from typing import Dict, List, Optional, Set


class GitError(RuntimeError):
    pass


def _git(args: List[str], cwd: str) -> str:
    try:
        out = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)
    except FileNotFoundError as exc:
        raise GitError("git is not installed") from exc
    except subprocess.CalledProcessError as exc:
        raise GitError(exc.stderr.strip() or f"git {' '.join(args)} failed") from exc
    return out.stdout


def repo_root(path: str) -> Optional[str]:
    try:
        return _git(["rev-parse", "--show-toplevel"], path).strip()
    except GitError:
        return None


def list_files(root: str) -> List[str]:
    """Tracked + untracked-but-not-ignored files, respecting .gitignore."""
    out = _git(["ls-files", "-z", "--cached", "--others", "--exclude-standard"], root)
    return sorted({p for p in out.split("\0") if p and os.path.isfile(os.path.join(root, p))})


def staged_files(root: str) -> List[str]:
    out = _git(["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"], root)
    return [p for p in out.split("\0") if p]


def merge_base(root: str, base: str) -> str:
    try:
        return _git(["merge-base", base, "HEAD"], root).strip()
    except GitError:
        return base


_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def changed_lines(root: str, base: Optional[str] = None, staged: bool = False) -> Dict[str, Set[int]]:
    """Map of path -> set of added/modified line numbers in the new version.

    ``base`` compares the working tree against the merge-base with that ref
    (what a PR would show). ``staged`` compares the index against HEAD.
    """
    if staged:
        args = ["diff", "--cached", "--unified=0", "--no-color", "--diff-filter=ACMR"]
    else:
        args = ["diff", "--unified=0", "--no-color", "--diff-filter=ACMR", merge_base(root, base or "HEAD")]
    diff = _git(args, root)
    result: Dict[str, Set[int]] = {}
    current: Optional[str] = None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            target = line[4:]
            current = target[2:] if target.startswith("b/") else None
            if current:
                result.setdefault(current, set())
        elif line.startswith("@@") and current:
            m = _HUNK_RE.match(line)
            if m:
                start, count = int(m.group(1)), int(m.group(2) or "1")
                result[current].update(range(start, start + count))
    if not staged:
        # Brand-new untracked files count as entirely changed.
        for path in _git(["ls-files", "--others", "--exclude-standard", "-z"], root).split("\0"):
            if path:
                result.setdefault(path, {-1})  # -1 => whole file
    return result


def head_sha(root: str) -> Optional[str]:
    try:
        return _git(["rev-parse", "HEAD"], root).strip()
    except GitError:
        return None
