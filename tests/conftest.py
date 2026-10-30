import os
import subprocess
import textwrap

import pytest

from codesift import engine
from codesift.config import load_config


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    """An empty git repository with helpers to write files and run codesift."""

    class Repo:
        root = tmp_path

        def write(self, rel, content, dedent=True):
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(textwrap.dedent(content) if dedent else content, encoding="utf-8")
            return p

        def read(self, rel):
            return (tmp_path / rel).read_text(encoding="utf-8")

        def git(self, *args):
            _git(tmp_path, *args)

        def commit(self, msg="commit"):
            self.git("add", "-A")
            self.git("commit", "-qm", msg)

        def run(self, **kwargs):
            cfg = load_config(str(tmp_path))
            return engine.run(cfg, **kwargs)

        def rule_ids(self, **kwargs):
            return [f.rule_id for f in self.run(**kwargs).findings]

    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "test")
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        yield Repo()
    finally:
        os.chdir(cwd)
