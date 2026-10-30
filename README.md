# codesift

Finds **bugs, performance problems, security slip-ups and style drift** in Python and
JavaScript/TypeScript (plus language-agnostic checks for every text file). The same
engine runs in three places:

| Where | What you get |
|---|---|
| **Terminal** | Colored report with source snippets, `--fix` for safe auto-fixes, `--fix-diff` preview |
| **git pre-commit hook** | Blocks a commit only for problems on the lines you're committing |
| **GitHub Actions** | Inline PR annotations, a sticky PR comment, one-click ```` ```suggestion ```` fixes, a job summary, and SARIF uploaded to **Security → Code scanning** |

It has **no runtime dependencies** (standard library only, Python ≥ 3.11) and checks a
typical repo in well under a second.

---

## Quick start

```bash
pip install git+https://github.com/<you>/codesift      # or: pip install -e . from this folder

cd your-repo
codesift init --github --hook   # learns your style, writes .codesift.toml, a workflow, and a pre-commit hook
codesift                        # analyze the whole repo
codesift --fix                  # apply safe fixes
```

`codesift init` reads your existing code and records **your** conventions (indent
width, tabs vs spaces, quote style, line length), so it enforces the style the project
already uses rather than an arbitrary one:

```
Detected python style from 42 file(s): indent=space/4, quotes=double, max line=100
    indent: 18211 space-indented vs 0 tab-indented lines; step sizes {4: 3120}
    line length: 99th percentile line is 97 chars
    quotes: 112 single-quoted vs 2210 double-quoted strings
```

## When it runs

| Trigger | Command | Scope |
|---|---|---|
| You, any time | `codesift` | whole repo (respects `.gitignore`) |
| Before pushing a branch | `codesift --changed origin/main` | only lines your branch changed |
| `git commit` | hook runs `codesift check --staged` | only staged lines |
| Pull request | `codesift ci` | only lines the PR changes, so you're never blamed for old code |
| Push to main | `codesift ci` | whole repo → Code scanning keeps a full picture |

## Adopting it on an existing codebase

Large repos usually have hundreds of existing findings. Record them once and codesift
will only report **new** ones:

```bash
codesift baseline          # writes .codesift-baseline.json; commit it
```

Then add `baseline = ".codesift-baseline.json"` to the config. Baseline entries are matched
by content fingerprint, not line number, so they survive unrelated edits that move code
around.

## GitHub integration

Use the bundled composite action. `.github/workflows/codesift.yml`:

```yaml
name: codesift
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  pull-requests: write     # sticky comment + suggested fixes
  security-events: write   # Code scanning upload

jobs:
  codesift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # required to diff against the PR base
      - uses: <you>/codesift@v1
        with:
          fail-on: error     # error | warning | info | never
          suggest: "true"    # one-click fix suggestions in the PR review
```

On a pull request, the action:

1. **Annotates** each finding inline on the *Files changed* tab (errors first).
2. Posts **one sticky comment** with a summary table and links to each line. Later runs
   edit that comment rather than adding new ones, and it is removed once the PR is clean
   (`comment: always` keeps it).
3. Opens a review with **```` ```suggestion ```` blocks** for auto-fixable issues, so a
   reviewer can click *Commit suggestion*. Issues it has already suggested aren't posted again.
4. Writes the same report to the **job summary**.
5. Uploads **SARIF** so findings appear under *Security → Code scanning* and are tracked
   across commits. On private repos without GitHub Advanced Security this step is skipped
   and doesn't fail the job.
6. Sets outputs `total`, `errors`, `warnings`, `sarif` for later steps.

| Input | Default | |
|---|---|---|
| `scope` | `auto` | `auto` = changed lines on PRs, whole repo on push; or `changed` / `all` |
| `fail-on` | `error` | lowest severity that fails the check |
| `comment` | `on-issues` | `always`, `on-issues`, `never` |
| `suggest` | `true` | post one-click fix suggestions |
| `upload-sarif` | `true` | upload to Code scanning |
| `args` | | extra CLI args, e.g. `--disable G020` |

Prefer not to use the action? `pip install` codesift and run `codesift ci --suggest`
with `GITHUB_TOKEN` set. `codesift check -f github` prints annotation commands on their own,
for any CI system that understands them.

## Pre-commit

Built-in hook: `codesift install-hook`. Or with the [pre-commit](https://pre-commit.com) framework:

```yaml
repos:
  - repo: https://github.com/<you>/codesift
    rev: v1.0.0
    hooks:
      - id: codesift        # or codesift-fix to auto-fix on commit
```

## Configuration

`.codesift.toml` (or `[tool.codesift]` in `pyproject.toml`). Every key is optional.
Precedence: defaults → `.editorconfig` → config → `[[overrides]]` → CLI flags.

```toml
[codesift]
max-line-length = 100
indent-style = "space"        # "space" | "tab" | "auto" (don't enforce)
indent-size = 4
quote-style = "double"        # "single" | "double" | "auto"
max-complexity = 12
max-function-length = 80
max-arguments = 7
fail-on = "error"
baseline = ".codesift-baseline.json"
extend-exclude = ["migrations/**"]
disable = ["G020", "no-var"]  # IDs, ID prefixes ("JS"), or names

[codesift.severity]
G003 = "warning"              # promote/demote any rule

[[codesift.overrides]]
paths = ["tests/**"]
disable = ["PY021", "JS002"]
max-function-length = 200
```

`.editorconfig` keys (`indent_style`, `indent_size`, `max_line_length`,
`insert_final_newline`, `trim_trailing_whitespace`, `quote_type`) are picked up
automatically.

### Suppressing a finding

```python
value = eval(expr)  # codesift: ignore[PY040]
# codesift: ignore-next-line[compare-to-none]
if x == None: ...
# codesift: ignore-file        (at the top of a generated file)
```

Inline suppressions work with any comment syntax (`#`, `//`, `/* */`, `<!-- -->`).

## CLI reference

```
codesift [check] [PATHS...]
    -f, --format {text,json,sarif,github,markdown}
    -o, --output FILE         write the report to a file
    --sarif FILE              also write SARIF
    --fix / --fix-diff        apply / preview safe fixes
    --changed [BASE]          only lines changed vs BASE (default HEAD)
    --staged                  only staged lines
    --select / --disable      rule IDs, prefixes or names (comma separated)
    --fail-on {error,warning,info,never}
    --no-baseline  --statistics  -q  --no-source  -j N
codesift ci        [--scope auto|changed|all] [--comment always|on-issues|never] [--suggest]
codesift init      [--github] [--hook] [--dry-run] [--force]
codesift baseline  [--file PATH]
codesift rules     [--markdown]
codesift install-hook
```

Exit codes: `0` clean (or only findings below `--fail-on`), `1` findings at or above
`--fail-on`, `2` usage/config/git error.

## How auto-fix stays safe

* Only rules where the fix can't change behavior beyond the intended one are marked
  fixable (e.g. `== None` → `is None`, removing an unused single-name import, dropping a
  pointless `f` prefix).
* A deleted statement that was the only statement in its block becomes `pass`.
* After fixing, Python files are re-parsed. If a fix would produce invalid code, that
  file is left untouched.
* Fixes run in passes until they settle, so several fixes on one line all get applied.
* `--fix-diff` shows exactly what would change before anything is written.

## Rules (46)

| ID | Name | Category | Default | Fix | Languages | Description |
|---|---|---|---|:-:|---|---|
| `G001` | trailing-whitespace | style | info | ✓ | all | Line has trailing whitespace. |
| `G002` | missing-final-newline | style | info | ✓ | all | File does not end with a newline. |
| `G003` | line-too-long | style | info |  | all | Line exceeds the configured maximum length. |
| `G004` | inconsistent-indentation | style | warning | ✓ | all | Indentation does not match the project's configured style (.editorconfig / .codesift.toml). |
| `G010` | merge-conflict-marker | bug | error |  | all | Unresolved git merge conflict marker. |
| `G011` | hardcoded-secret | security | error |  | all | Credential or private key committed to source. |
| `G020` | todo-comment | maintainability | info |  | all | TODO/FIXME comment (tracked so they don't get lost). |
| `JS001` | loose-equality | bug | warning | ✓ | javascript, typescript | `==`/`!=` perform type coercion; use `===`/`!==`. |
| `JS002` | console-log | maintainability | warning |  | javascript, typescript | Leftover console logging. |
| `JS003` | debugger-statement | bug | error | ✓ | javascript, typescript | `debugger` statement left in code. |
| `JS004` | no-var | style | info |  | javascript, typescript | `var` is function-scoped and hoisted; prefer `let`/`const`. |
| `JS005` | await-in-loop | performance | info |  | javascript, typescript | Sequential `await` inside a loop; independent work could run in parallel. |
| `JS006` | empty-catch | bug | warning |  | javascript, typescript | Empty `catch` block silently swallows errors. |
| `JS007` | quote-style | style | info |  | javascript, typescript | String quotes don't match the project's preferred quote style. |
| `JS008` | ts-any | maintainability | info |  | typescript | Explicit `any` disables type checking. |
| `PY001` | syntax-error | bug | error |  | python | File cannot be parsed as Python. |
| `PY002` | bare-except | bug | warning | ✓ | python | Bare `except:` also catches KeyboardInterrupt and SystemExit. |
| `PY003` | mutable-default-argument | bug | error |  | python | Mutable default argument is shared between calls. |
| `PY004` | compare-to-none | bug | warning | ✓ | python | Use `is None` / `is not None` instead of `==`/`!=`. |
| `PY005` | is-literal | bug | error | ✓ | python | `is` compares identity, not value, for str/int/bytes literals. |
| `PY006` | duplicate-dict-key | bug | error |  | python | Dictionary literal repeats a key; the earlier value is lost. |
| `PY007` | assert-on-tuple | bug | error |  | python | `assert (cond, msg)` is always true. |
| `PY008` | redefined-function | bug | warning |  | python | Function or class is defined twice in the same scope. |
| `PY009` | open-without-with | bug | warning |  | python | File opened without a context manager may never be closed. |
| `PY010` | debugger-left-in | bug | error | ✓ | python | Debugger breakpoint left in code. |
| `PY011` | swallowed-exception | bug | warning |  | python | Exception is caught and silently ignored. |
| `PY012` | fstring-without-placeholders | style | info | ✓ | python | f-string has no placeholders. |
| `PY020` | unused-import | maintainability | warning | ✓ | python | Imported name is never used. |
| `PY021` | unused-variable | maintainability | warning |  | python | Local variable is assigned but never read. |
| `PY022` | unreachable-code | maintainability | warning |  | python | Statement can never execute. |
| `PY023` | shadowed-builtin | maintainability | warning |  | python | Name shadows a Python builtin. |
| `PY024` | high-complexity | maintainability | warning |  | python | Function's cyclomatic complexity exceeds the limit. |
| `PY025` | too-many-arguments | maintainability | info |  | python | Function takes too many parameters. |
| `PY026` | function-too-long | maintainability | info |  | python | Function body is longer than the configured limit. |
| `PY030` | string-concat-in-loop | performance | warning |  | python | Building a string with `+=` inside a loop is quadratic. |
| `PY031` | range-len-loop | style | info |  | python | `for i in range(len(x))` where `enumerate` is clearer and faster. |
| `PY032` | unnecessary-list-in-any-all | performance | info | ✓ | python | `any([...])`/`all([...])` builds the whole list and can't short-circuit. |
| `PY033` | membership-on-keys | performance | info |  | python | `x in d.keys()` / `x in list(...)` is slower than `x in d`. |
| `PY034` | sorted-for-min-max | performance | info |  | python | `sorted(x)[0]` / `sorted(x)[-1]` is O(n log n); use min()/max(). |
| `PY035` | mutate-while-iterating | bug | error |  | python | Collection is modified while it is being iterated over. |
| `PY040` | eval-exec | security | warning |  | python | `eval`/`exec` on dynamic input enables code injection. |
| `PY041` | subprocess-shell-true | security | warning |  | python | `shell=True` passes the command through the shell. |
| `PY042` | requests-without-timeout | bug | warning |  | python | HTTP request without a timeout can hang forever. |
| `PY050` | compare-to-bool | style | info |  | python | Comparing to True/False with `==` is redundant. |
| `PY051` | len-as-condition | style | info |  | python | `len(x) == 0` / `len(x) > 0` instead of truthiness. |
| `PY052` | quote-style | style | info |  | python | String quotes don't match the project's preferred quote style. |

## Adding a rule

Rules are plain functions registered with a decorator. A rule yields findings and can
attach a `Fix`:

```python
# src/codesift/rules/python.py
@rule("PY060", "print-in-library", "print() in library code.",
      category=Category.MAINTAINABILITY, severity=Severity.INFO, languages=("python",))
def print_in_library(src, ctx):
    for node in _all_nodes(parse(src)):
        if isinstance(node, ast.Call) and _name(node.func) == "print":
            yield make_finding(print_in_library.rule, src, node.lineno, "print() call.")
```

Add a positive and a negative case to `tests/test_rules.py`, and it automatically shows
up in `codesift rules`, SARIF metadata and the Code scanning UI.

## Project layout

```
action.yml                     GitHub composite action
.pre-commit-hooks.yaml         pre-commit framework hooks
src/codesift/
  cli.py                       commands: check, ci, init, baseline, rules, install-hook
  engine.py                    discovery (.gitignore-aware), suppressions, baseline, diff filtering
  config.py                    .codesift.toml / pyproject / .editorconfig resolution
  style.py                     infers a repo's existing conventions for `init`
  fixer.py                     applies fixes
  reporters.py                 text, json, sarif, github, markdown
  github.py                    job summary, sticky PR comment, suggestion reviews (stdlib urllib)
  rules/                       generic.py, python.py (AST), javascript.py (string/comment-aware)
tests/                         94 tests, including a fake GitHub API for the PR flow
```

## Limitations

* JavaScript/TypeScript checks are lexical: strings and comments are masked out, but no
  JS parser is involved, so for deep JS analysis pair codesift with ESLint.
* `--staged` analyzes the working-tree version of staged files. If you've edited a file
  further after staging it, results reflect those edits too.
* Suggested-change review comments can only target lines inside the PR diff, which is
  the default `scope` on PRs.
