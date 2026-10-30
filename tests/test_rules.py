"""Each rule: one snippet that must trigger it, and one similar snippet that must not."""

import textwrap

import pytest

from codesift.config import Config
from codesift.engine import analyze_file
from codesift.models import SourceFile
from codesift.rules import python as py_rules, javascript as js_rules


def findings(code, path="mod.py", **settings):
    cfg = Config(root="/nonexistent")
    cfg.settings.update(settings)
    text = textwrap.dedent(code)
    lang = {"py": "python", "js": "javascript", "ts": "typescript", "md": "markdown"}[path.rsplit(".", 1)[1]]
    src = SourceFile(path=path, abs_path=path, text=text, language=lang)
    try:
        return analyze_file(src, cfg)
    finally:
        py_rules.clear_cache()
        js_rules.clear_cache()


def ids(code, **kw):
    return {f.rule_id for f in findings(code, **kw)}


POSITIVE = [
    ("PY001", "def f(:\n    pass\n"),
    ("PY002", "try:\n    x = 1\nexcept:\n    raise\n"),
    ("PY003", "def f(a, b=[]):\n    return b\n"),
    ("PY003", "def f(a, *, b=dict()):\n    return b\n"),
    ("PY004", "def f(x):\n    return x == None\n"),
    ("PY005", "def f(x):\n    return x is 'a'\n"),
    ("PY006", "D = {'a': 1, 'b': 2, 'a': 3}\n"),
    ("PY007", "assert (1 == 2, 'msg')\n"),
    ("PY008", "def f():\n    pass\n\n\ndef f():\n    pass\n"),
    ("PY009", "def f():\n    fh = open('x')\n    return fh.read()\n"),
    ("PY010", "def f():\n    breakpoint()\n    return 1\n"),
    ("PY010", "import pdb\n\ndef f():\n    pdb.set_trace()\n"),
    ("PY011", "try:\n    x = 1\nexcept Exception:\n    pass\n"),
    ("PY012", "print(f'hello')\n"),
    ("PY020", "import os\nprint(1)\n"),
    ("PY021", "def f():\n    unused = 1\n    return 2\n"),
    ("PY022", "def f():\n    return 1\n    print('x')\n"),
    ("PY023", "def f(list):\n    return list\n"),
    ("PY030", "def f(xs):\n    s = ''\n    for x in xs:\n        s += x\n    return s\n"),
    ("PY031", "def f(xs):\n    for i in range(len(xs)):\n        print(xs[i])\n"),
    ("PY032", "def f(xs):\n    return any([x > 1 for x in xs])\n"),
    ("PY033", "def f(d, k):\n    return k in d.keys()\n"),
    ("PY034", "def f(xs):\n    return sorted(xs)[0]\n"),
    ("PY035", "def f(xs):\n    for x in xs:\n        xs.append(x)\n"),
    ("PY040", "def f(s):\n    return eval(s)\n"),
    ("PY041", "import subprocess\n\ndef f(c):\n    subprocess.run(c, shell=True)\n"),
    ("PY042", "import requests\n\ndef f():\n    return requests.get('http://x')\n"),
    ("PY050", "def f(x):\n    return x == True\n"),
    ("PY051", "def f(x):\n    return len(x) == 0\n"),
    ("G001", "x = 1   \n"),
    ("G002", "x = 1"),
    ("G010", "<<<<<<< HEAD\nx = 1\n=======\nx = 2\n>>>>>>> branch\n"),
    ("G011", "TOKEN = 'ghp_" + "a" * 36 + "'\n"),
    ("G011", "password = 'hunter2hunter2'\n"),
    ("G020", "# TODO: remove this\nx = 1\n"),
]

NEGATIVE = [
    ("PY002", "try:\n    x = 1\nexcept ValueError:\n    raise\n"),
    ("PY003", "def f(a, b=None, c=()):\n    return b\n"),
    ("PY004", "def f(x):\n    return x is None\n"),
    ("PY005", "def f(x):\n    return x is None or x is True or x is ...\n"),
    ("PY006", "D = {'a': 1, 'b': 2, 1: 3, '1': 4}\n"),
    ("PY008", "class A:\n    @property\n    def x(self):\n        return 1\n\n    @x.setter\n    def x(self, v):\n"
              "        pass\n"),
    ("PY009", "def f():\n    with open('x') as fh:\n        return fh.read()\n"),
    ("PY011", "try:\n    x = 1\nexcept (KeyError, ValueError):\n    pass\n"),
    ("PY012", "x = 1\nprint(f'{x}')\nprint(f'{x:>{10}}')\n"),
    ("PY020", "import os\nprint(os.sep)\n"),
    ("PY020", "from typing import TYPE_CHECKING\nx: 'TYPE_CHECKING' = 1\n"),
    ("PY021", "def f():\n    a, b = 1, 2\n    _ignored = 3\n    used = 4\n    return used + a\n"),
    ("PY021", "def f():\n    x = 1\n\n    def g():\n        return x\n    return g\n"),
    ("PY023", "from dataclasses import dataclass\n\n@dataclass\nclass A:\n    id: int\n    type: str\n"),
    ("PY030", "def f(xs):\n    n = 0\n    for x in xs:\n        n += x\n    return n\n"),
    ("PY031", "def f(xs):\n    for i in range(len(xs)):\n        print(i)\n"),
    ("PY034", "def f(xs):\n    return sorted(xs)[1]\n"),
    ("PY040", "eval('1 + 1')\n"),
    ("PY041", "import subprocess\n\nsubprocess.run('ls -la', shell=True)\n"),
    ("PY042", "import requests\n\nrequests.get('http://x', timeout=5)\n"),
    ("G010", "Title\n=======\n"),
    ("G011", "password = 'changeme'\napi_key = os.environ['API_KEY']\npassword = '${SECRET_VALUE}'\n"),
]


@pytest.mark.parametrize("rule_id,code", POSITIVE, ids=[f"{r}-{i}" for i, (r, _) in enumerate(POSITIVE)])
def test_rule_triggers(rule_id, code):
    assert rule_id in ids(code)


@pytest.mark.parametrize("rule_id,code", NEGATIVE, ids=[f"{r}-{i}" for i, (r, _) in enumerate(NEGATIVE)])
def test_rule_quiet(rule_id, code):
    assert rule_id not in ids(code)


def test_complexity_and_length_limits():
    branches = "\n".join(f"    if x == {i}:\n        return {i}" for i in range(6))
    code = f"def f(x):\n{branches}\n    return -1\n"
    assert "PY024" in ids(code, **{"max-complexity": 5})
    assert "PY024" not in ids(code, **{"max-complexity": 10})
    assert "PY026" in ids(code, **{"max-function-length": 5})
    assert "PY025" in ids("def f(a, b, c, d):\n    pass\n", **{"max-arguments": 3})


def test_line_length_respects_setting():
    code = "x = '" + "a " * 60 + "'\n"
    assert "G003" in ids(code, **{"max-line-length": 80})
    assert "G003" not in ids(code, **{"max-line-length": 200})


def test_indentation_style():
    code = "def f():\n\treturn 1\n"
    assert "G004" in ids(code, **{"indent-style": "space"})
    assert "G004" not in ids(code)  # not enforced unless configured


def test_quote_style():
    assert "PY052" in ids("x = 'a'\n", **{"quote-style": "double"})
    assert "PY052" not in ids("x = \"it's\"\n", **{"quote-style": "single"})
    assert "JS007" in ids("const a = 'x';\n", path="a.js", **{"quote-style": "double"})


# --- JavaScript / TypeScript ----------------------------------------------------

JS_POSITIVE = [
    ("JS001", "if (a == 1) {}\n"),
    ("JS002", "console.log('hi');\n"),
    ("JS003", "function f() {\n  debugger;\n}\n"),
    ("JS004", "var x = 1;\n"),
    ("JS005", "async function f(us) {\n  for (const u of us) {\n    await fetch(u);\n  }\n}\n"),
    ("JS006", "try { a(); } catch (e) {}\n"),
]
JS_NEGATIVE = [
    ("JS001", "if (a === 1 || b !== 2 || c == null) {}\nconst s = 'a == b'; // x == y\n"),
    ("JS002", "/* console.log('x') */\nconst s = \"console.log(1)\";\n"),
    ("JS004", "let variable = 1; const vary = 2;\n"),
    ("JS005", "async function f(us) {\n  await Promise.all(us.map(fetch));\n}\n"),
    ("JS006", "try { a(); } catch (e) { /* optional feature */ }\n"),
]


@pytest.mark.parametrize("rule_id,code", JS_POSITIVE)
def test_js_rule_triggers(rule_id, code):
    assert rule_id in ids(code, path="app.js")


@pytest.mark.parametrize("rule_id,code", JS_NEGATIVE)
def test_js_rule_quiet(rule_id, code):
    assert rule_id not in ids(code, path="app.js")


def test_ts_any():
    assert "JS008" in ids("let x: any = 1;\n", path="a.ts")
    assert "JS008" not in ids("let x: any = 1;\n", path="a.js")


def test_markdown_trailing_spaces_allowed():
    assert "G001" not in ids("line one  \nline two\n", path="README.md")


# --- suppression ----------------------------------------------------------------

def test_inline_suppression():
    assert "PY004" not in ids("def f(x):\n    return x == None  # codesift: ignore[PY004]\n")
    assert "PY004" not in ids("def f(x):\n    return x == None  # codesift: ignore\n")
    assert "PY004" in ids("def f(x):\n    return x == None  # codesift: ignore[PY005]\n")


def test_next_line_and_file_suppression():
    assert "PY004" not in ids("def f(x):\n    # codesift: ignore-next-line[compare-to-none]\n    return x == None\n")
    assert ids("# codesift: ignore-file\nimport os\nx = 1   \n") == set()
