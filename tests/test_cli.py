import json
import os
import subprocess
import sys

from codesift.cli import main


BUGGY = """\
import os


def load(path, cache={}):
    if path == None:
        return None
    if path is "config":
        print(f"loading")
    return path
"""


def test_exit_codes(repo, capsys):
    repo.write("a.py", "x = 1\n")
    assert main(["check"]) == 0
    repo.write("b.py", BUGGY)
    assert main(["check"]) == 1                       # PY003/PY005 are errors
    assert main(["check", "--fail-on", "never"]) == 0
    assert main(["check", "--disable", "PY003,PY005"]) == 0
    assert main(["check", "--select", "PY020", "--fail-on", "warning"]) == 1


def test_fix_rewrites_file_and_keeps_it_valid(repo, capsys):
    repo.write("b.py", BUGGY + "\n\ndef dbg(x):\n    if x:\n        breakpoint()\n    return x   ")
    main(["check", "--fix"])
    fixed = repo.read("b.py")
    compile(fixed, "b.py", "exec")
    assert "import os" not in fixed
    assert "path is None" in fixed
    assert 'path == "config"' in fixed
    assert 'print("loading")' in fixed
    assert "breakpoint" not in fixed and "        pass" in fixed
    assert fixed.endswith("return x\n")


def test_fix_diff_does_not_write(repo, capsys):
    repo.write("b.py", "x = 1   \n")
    main(["check", "--fix-diff"])
    out = capsys.readouterr().out
    assert "-x = 1   " in out and "+x = 1" in out
    assert repo.read("b.py") == "x = 1   \n"


def test_json_and_sarif_output(repo, capsys):
    repo.write("b.py", BUGGY)
    main(["check", "-f", "json", "--sarif", "out.sarif"])
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["error"] >= 2
    assert {f["rule"] for f in data["findings"]} >= {"PY003", "PY004", "PY005", "PY020"}

    sarif = json.loads(repo.read("out.sarif"))
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    for r in run["tool"]["driver"]["rules"]:
        tags = r.get("properties", {}).get("tags", [])
        assert len(tags) == len(set(tags))  # SARIF requires unique tags
    for res in run["results"]:
        assert rule_ids[res["ruleIndex"]] == res["ruleId"]
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "b.py"
        assert loc["region"]["startLine"] >= 1


def test_github_annotations(repo, capsys):
    repo.write("b.py", BUGGY)
    main(["check", "-f", "github"])
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("::error file=b.py,line=")
    assert any(line.startswith("::warning ") for line in out)


def test_baseline_hides_existing_but_reports_new(repo, capsys):
    repo.write(".codesift.toml", '[codesift]\nbaseline = ".codesift-baseline.json"\n')
    repo.write("b.py", BUGGY)
    assert main(["baseline"]) == 0
    assert main(["check"]) == 0
    # Shifting code down must not invalidate the baseline.
    repo.write("b.py", "\n\n" + BUGGY)
    assert main(["check"]) == 0
    repo.write("b.py", BUGGY + "\n\ndef g(x=[]):\n    return x\n")
    assert main(["check"]) == 1
    assert main(["check", "--no-baseline", "-q"]) == 1


def test_changed_lines_only(repo, capsys):
    repo.write("b.py", BUGGY)
    repo.commit()
    assert main(["check", "--changed"]) == 0           # nothing changed
    repo.write("b.py", BUGGY + "\n\ndef g(x=[]):\n    return x\n")
    capsys.readouterr()
    assert main(["check", "--changed", "-f", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert {f["rule"] for f in data["findings"]} == {"PY003"}
    assert all(f["line"] > 9 for f in data["findings"])


def test_staged_mode(repo, capsys):
    repo.write("ok.py", "x = 1\n")
    repo.commit()
    repo.write("bad.py", "def g(x=[]):\n    return x\n")
    assert main(["check", "--staged"]) == 0            # not staged yet
    repo.git("add", "bad.py")
    assert main(["check", "--staged"]) == 1


def test_config_editorconfig_and_overrides(repo):
    repo.write(".editorconfig", "root = true\n\n[*.py]\nindent_style = space\nindent_size = 4\nmax_line_length = 40\n")
    repo.write("a.py", "def f():\n\treturn 'this line is definitely longer than forty chars'\n")
    found = set(repo.rule_ids())
    assert {"G003", "G004"} <= found
    repo.write(".codesift.toml", """
        [codesift]
        max-line-length = 200
        [[codesift.overrides]]
        paths = ["a.py"]
        disable = ["G004"]
    """)
    found = set(repo.rule_ids())
    assert "G003" not in found and "G004" not in found


def test_gitignore_respected(repo):
    repo.write(".gitignore", "generated/\n")
    repo.write("generated/x.py", "import os\n")
    repo.write("node_modules/pkg/index.js", "debugger;\n")
    repo.write("src/y.py", "import os\n")
    paths = {f.path for f in repo.run().findings}
    assert paths == {"src/y.py"}


def test_init_infers_style(repo, capsys):
    for i in range(5):
        repo.write(f"m{i}.py", "def f(x):\n  if x:\n    return 'a' + 'b' + 'c' + 'd'\n  return 'e'\n")
    assert main(["init", "--github"]) == 0
    cfg = repo.read(".codesift.toml")
    assert "indent-size = 2" in cfg
    assert 'quote-style = "single"' in cfg
    assert "pull-requests: write" in repo.read(".github/workflows/codesift.yml")
    # The generated config is valid and the repo passes its own inferred style.
    assert main(["check", "--select", "G004,PY052"]) == 0


def test_install_hook_blocks_bad_commit(repo):
    repo.write("ok.py", "x = 1\n")
    repo.commit()
    env = {**os.environ, "PYTHONPATH": os.path.join(os.path.dirname(__file__), "..", "src")}
    assert main(["install-hook"]) == 0
    hook = repo.root / ".git" / "hooks" / "pre-commit"
    assert hook.exists() and os.access(hook, os.X_OK)
    repo.write("bad.py", "def g(x=[]):\n    return x\n")
    repo.git("add", "bad.py")
    proc = subprocess.run(["git", "commit", "-m", "bad"], cwd=repo.root, capture_output=True, text=True, env=env)
    assert proc.returncode != 0
    assert "PY003" in proc.stdout + proc.stderr


def test_rules_command(capsys):
    assert main(["rules", "--markdown"]) == 0
    out = capsys.readouterr().out
    assert "| `PY003` |" in out


def test_module_entrypoint():
    proc = subprocess.run([sys.executable, "-m", "codesift", "--version"], capture_output=True, text=True,
                          env={**os.environ, "PYTHONPATH": os.path.join(os.path.dirname(__file__), "..", "src")})
    assert proc.stdout.startswith("codesift ")


def test_explicit_paths_override_user_excludes(repo, capsys):
    repo.write(".codesift.toml", '[codesift]\nextend-exclude = ["legacy/**"]\n')
    repo.write("legacy/old.py", "import os\n")
    repo.write("legacy/node_modules/x.js", "debugger;\n")
    assert main(["check", "-q", "--fail-on", "warning"]) == 0           # excluded by config
    assert main(["check", "legacy", "-q", "--fail-on", "warning"]) == 1  # named explicitly
    capsys.readouterr()
    main(["check", "legacy", "-f", "json"])
    import json as _json
    paths = {f["path"] for f in _json.loads(capsys.readouterr().out)["findings"]}
    assert paths == {"legacy/old.py"}                                    # built-in excludes still apply
