"""GitHub integration: job summary, sticky PR comment, and suggested-change reviews.

Uses only urllib so the action needs no extra dependencies.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import List, Optional

from .engine import RunResult
from .models import Finding
from .reporters import COMMENT_MARKER

SUGGESTION_MARKER = "<!-- codesift-suggestion:{fp} -->"


@dataclass
class GitHubContext:
    token: str
    repo: str              # "owner/name"
    api_url: str
    server_url: str
    pr_number: Optional[int]
    head_sha: Optional[str]

    @classmethod
    def from_env(cls) -> Optional["GitHubContext"]:
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("INPUT_GITHUB_TOKEN")
        repo = os.environ.get("GITHUB_REPOSITORY")
        if not token or not repo:
            return None
        pr_number = None
        head_sha = os.environ.get("GITHUB_SHA")
        event_path = os.environ.get("GITHUB_EVENT_PATH")
        if event_path and os.path.isfile(event_path):
            with open(event_path, encoding="utf-8") as fh:
                event = json.load(fh)
            pr = event.get("pull_request")
            if pr:
                pr_number = pr.get("number")
                head_sha = pr.get("head", {}).get("sha", head_sha)
        return cls(token=token, repo=repo,
                   api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/"),
                   server_url=os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/"),
                   pr_number=pr_number, head_sha=head_sha)

    @property
    def blob_base(self) -> Optional[str]:
        if not self.head_sha:
            return None
        return f"{self.server_url}/{self.repo}/blob/{self.head_sha}"

    # -- HTTP -------------------------------------------------------------

    def request(self, method: str, path: str, body: Optional[dict] = None):
        url = path if path.startswith("http") else f"{self.api_url}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "codesift",
            **({"Content-Type": "application/json"} if data else {}),
        })
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else None

    def paginate(self, path: str) -> List[dict]:
        items: List[dict] = []
        page = 1
        sep = "&" if "?" in path else "?"
        while True:
            batch = self.request("GET", f"{path}{sep}per_page=100&page={page}") or []
            items.extend(batch)
            if len(batch) < 100:
                return items
            page += 1


def write_step_summary(markdown: str) -> bool:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return False
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(markdown + "\n")
    return True


def set_outputs(**values) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        for k, v in values.items():
            fh.write(f"{k}={v}\n")


def upsert_pr_comment(gh: GitHubContext, markdown: str, *, delete_when_clean: bool = False,
                      clean: bool = False) -> str:
    """Create or update the single codesift comment on the PR. Returns the action taken."""
    if not gh.pr_number:
        return "skipped (not a pull request)"
    comments = gh.paginate(f"/repos/{gh.repo}/issues/{gh.pr_number}/comments")
    existing = next((c for c in comments if COMMENT_MARKER in (c.get("body") or "")), None)
    if clean and delete_when_clean:
        if existing:
            gh.request("DELETE", f"/repos/{gh.repo}/issues/comments/{existing['id']}")
            return "deleted"
        return "skipped (clean)"
    if existing:
        if existing.get("body") == markdown:
            return "unchanged"
        gh.request("PATCH", f"/repos/{gh.repo}/issues/comments/{existing['id']}", {"body": markdown})
        return "updated"
    if clean:
        return "skipped (clean, no previous comment)"
    gh.request("POST", f"/repos/{gh.repo}/issues/{gh.pr_number}/comments", {"body": markdown})
    return "created"


def post_suggestions(gh: GitHubContext, result: RunResult, *, limit: int = 20) -> int:
    """Post a PR review whose comments contain ```suggestion blocks for fixable findings.

    Reviewers can apply each fix with one click ("Commit suggestion"). Findings
    already suggested in a previous run are skipped. Only lines that are part of
    the PR diff can be commented on, so run with ``--diff`` for best results.
    """
    if not gh.pr_number or not gh.head_sha:
        return 0
    existing = gh.paginate(f"/repos/{gh.repo}/pulls/{gh.pr_number}/comments")
    already = " ".join(c.get("body") or "" for c in existing)

    comments = []
    for f in result.findings:
        if not f.fix or f.fix.line != f.line:
            continue
        marker = SUGGESTION_MARKER.format(fp=f.fingerprint())
        if marker in already:
            continue
        comments.append(_suggestion_comment(f, marker))
        if len(comments) >= limit:
            break
    if not comments:
        return 0
    body = {
        "commit_id": gh.head_sha,
        "event": "COMMENT",
        "body": f"🛠️ codesift found {len(comments)} issue(s) it can fix automatically.",
        "comments": comments,
    }
    try:
        gh.request("POST", f"/repos/{gh.repo}/pulls/{gh.pr_number}/reviews", body)
    except urllib.error.HTTPError as exc:
        if exc.code != 422:
            raise
        # 422 = at least one line isn't in the diff. Fall back to posting individually.
        posted = 0
        for c in comments:
            try:
                gh.request("POST", f"/repos/{gh.repo}/pulls/{gh.pr_number}/comments",
                           {**c, "commit_id": gh.head_sha})
                posted += 1
            except urllib.error.HTTPError:
                continue
        return posted
    return len(comments)


def _suggestion_comment(f: Finding, marker: str) -> dict:
    # An empty suggestion block deletes the line.
    suggestion = "" if f.fix.replacement is None else f.fix.replacement + "\n"
    return {
        "path": f.path,
        "line": f.line,
        "side": "RIGHT",
        "body": f"**{f.rule_id}** {f.message}\n\n```suggestion\n{suggestion}```\n{marker}",
    }
