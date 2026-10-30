"""`codesift ci` against a fake GitHub API."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from codesift.cli import main
from codesift.reporters import COMMENT_MARKER


class FakeGitHub:
    def __init__(self):
        self.comments = []          # issue comments
        self.reviews = []
        self.review_comments = []
        self.calls = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body=None):
                data = json.dumps(body).encode() if body is not None else b""
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n)) if n else None

            def do_GET(self):
                fake.calls.append(("GET", self.path))
                if "/issues/7/comments" in self.path:
                    return self._send(200, fake.comments if "page=1" in self.path else [])
                if "/pulls/7/comments" in self.path:
                    return self._send(200, fake.review_comments if "page=1" in self.path else [])
                self._send(404, {})

            def do_POST(self):
                body = self._body()
                fake.calls.append(("POST", self.path))
                if self.path.endswith("/issues/7/comments"):
                    fake.comments.append({"id": len(fake.comments) + 1, "body": body["body"]})
                    return self._send(201, fake.comments[-1])
                if self.path.endswith("/pulls/7/reviews"):
                    fake.reviews.append(body)
                    fake.review_comments.extend(body["comments"])
                    return self._send(200, {})
                self._send(404, {})

            def do_PATCH(self):
                body = self._body()
                fake.calls.append(("PATCH", self.path))
                cid = int(self.path.rsplit("/", 1)[1])
                for c in fake.comments:
                    if c["id"] == cid:
                        c["body"] = body["body"]
                self._send(200, {})

            def do_DELETE(self):
                fake.calls.append(("DELETE", self.path))
                cid = int(self.path.rsplit("/", 1)[1])
                fake.comments = [c for c in fake.comments if c["id"] != cid]
                self._send(204)

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


@pytest.fixture
def gh_env(repo, tmp_path_factory, monkeypatch):
    fake = FakeGitHub()
    work = tmp_path_factory.mktemp("gh")
    event = work / "event.json"
    event.write_text(json.dumps({"pull_request": {"number": 7, "head": {"sha": "deadbeef"}}}))
    env = {
        "GITHUB_ACTIONS": "true", "GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": "octo/demo",
        "GITHUB_API_URL": fake.url, "GITHUB_EVENT_NAME": "pull_request", "GITHUB_BASE_REF": "main",
        "GITHUB_EVENT_PATH": str(event), "GITHUB_WORKSPACE": str(repo.root),
        "GITHUB_STEP_SUMMARY": str(work / "summary.md"), "GITHUB_OUTPUT": str(work / "output.txt"),
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    # Simulate actions/checkout with fetch-depth: 0 on a PR branch.
    repo.write("base.py", "def old(x=[]):\n    return x\n")
    repo.commit("base")
    repo.git("update-ref", "refs/remotes/origin/main", "HEAD")
    repo.git("checkout", "-qb", "feature")
    fake.work = work
    return fake


def test_ci_pull_request_flow(repo, gh_env, capsys):
    repo.write("new.py", "def added(a):\n    if a == None:\n        return 1\n    return 2\n")
    repo.commit("feature")

    code = main(["ci", "--suggest"])
    out = capsys.readouterr().out
    assert code == 0                                    # only a warning; fail-on defaults to error
    assert "::warning file=new.py,line=2" in out
    assert "base.py" not in out                         # pre-existing issue outside the PR diff

    # Sticky comment created with marker + blob links.
    assert len(gh_env.comments) == 1
    body = gh_env.comments[0]["body"]
    assert COMMENT_MARKER in body
    assert "/octo/demo/blob/deadbeef/new.py#L2" in body

    # One-click suggestion for the fixable finding.
    assert len(gh_env.reviews) == 1
    sugg = gh_env.reviews[0]["comments"][0]
    assert sugg["path"] == "new.py" and sugg["line"] == 2
    assert "```suggestion\n    if a is None:\n```" in sugg["body"]

    outputs = (gh_env.work / "output.txt").read_text()
    assert "total=1" in outputs and "scope=changed" in outputs
    assert (gh_env.work / "summary.md").read_text().startswith(COMMENT_MARKER)
    assert (repo.root / "codesift.sarif").exists()

    # Second run: comment is updated in place (not duplicated), suggestion not re-posted.
    main(["ci", "--suggest"])
    assert len(gh_env.comments) == 1
    assert len(gh_env.reviews) == 1

    # Fix the issue: the sticky comment is removed.
    repo.write("new.py", "def added(a):\n    if a is None:\n        return 1\n    return 2\n")
    repo.commit("fix")
    assert main(["ci"]) == 0
    assert gh_env.comments == []
    assert any(c[0] == "DELETE" for c in gh_env.calls)


def test_ci_fails_on_error(repo, gh_env, capsys):
    repo.write("new.py", "def added(a=[]):\n    return a\n")
    repo.commit("feature")
    assert main(["ci", "--comment", "never"]) == 1
    assert gh_env.comments == []


def test_ci_falls_back_when_base_missing(repo, gh_env, monkeypatch, capsys):
    monkeypatch.setenv("GITHUB_BASE_REF", "does-not-exist")
    repo.write("new.py", "x = 1\n")
    repo.commit("feature")
    main(["ci", "--comment", "never"])
    out = capsys.readouterr().out
    # Either git resolves nothing and we fall back to a full scan, which then sees base.py.
    assert "base.py" in out
