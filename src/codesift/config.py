"""Configuration loading.

Settings are resolved per file, lowest to highest precedence:

1. built-in defaults
2. ``.editorconfig`` (indentation, max_line_length, final newline, ...)
3. ``[tool.codesift]`` in ``pyproject.toml`` or a ``.codesift.toml`` file
4. ``[[overrides]]`` blocks in that config whose ``paths`` match the file
5. command-line flags
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field, replace
from typing import Dict, List, Optional

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    try:
        import tomli as tomllib  # type: ignore
    except ModuleNotFoundError:
        tomllib = None  # type: ignore

from .models import RuleContext, Severity

CONFIG_FILENAMES = (".codesift.toml", "codesift.toml")

DEFAULT_EXCLUDES = [
    ".git/**", "node_modules/**", "**/node_modules/**", "vendor/**", "dist/**", "build/**",
    ".venv/**", "venv/**", "**/__pycache__/**", ".tox/**", ".mypy_cache/**", "**/*.min.js",
    "**/*.lock", "package-lock.json", "**/*.map", ".codesift-baseline.json",
]

LANGUAGE_BY_EXT = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".md": "markdown", ".markdown": "markdown",
    ".json": "json", ".yml": "yaml", ".yaml": "yaml", ".toml": "toml",
    ".sh": "shell", ".bash": "shell", ".go": "go", ".rs": "rust", ".java": "java",
    ".rb": "ruby", ".c": "c", ".h": "c", ".cpp": "cpp", ".hpp": "cpp", ".cs": "csharp",
    ".css": "css", ".scss": "css", ".html": "html", ".sql": "sql", ".txt": "text",
}
LANGUAGE_BY_NAME = {"Makefile": "makefile", "Dockerfile": "dockerfile"}


def detect_language(path: str) -> Optional[str]:
    base = os.path.basename(path)
    if base in LANGUAGE_BY_NAME:
        return LANGUAGE_BY_NAME[base]
    return LANGUAGE_BY_EXT.get(os.path.splitext(base)[1].lower())


def glob_match(path: str, pattern: str) -> bool:
    """fnmatch with `**/` meaning "zero or more directories"."""
    if fnmatch.fnmatch(path, pattern):
        return True
    if pattern.startswith("**/") and fnmatch.fnmatch(path, pattern[3:]):
        return True
    if "/**/" in pattern and fnmatch.fnmatch(path, pattern.replace("/**/", "/")):
        return True
    if pattern.endswith("/**") and (path == pattern[:-3] or path.startswith(pattern[:-2])):
        return True
    return False


# --------------------------------------------------------------------------
# .editorconfig
# --------------------------------------------------------------------------


def _expand_braces(pattern: str) -> List[str]:
    m = re.search(r"\{([^{}]*)\}", pattern)
    if not m:
        return [pattern]
    out = []
    for alt in m.group(1).split(","):
        out.extend(_expand_braces(pattern[:m.start()] + alt + pattern[m.end():]))
    return out


@dataclass
class EditorConfig:
    sections: List[tuple] = field(default_factory=list)  # [(patterns, {key: value})]

    @classmethod
    def load(cls, root: str) -> "EditorConfig":
        path = os.path.join(root, ".editorconfig")
        ec = cls()
        if not os.path.isfile(path):
            return ec
        current = None
        with open(path, encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith(("#", ";")):
                    continue
                if line.startswith("[") and line.endswith("]"):
                    current = ({}, _expand_braces(line[1:-1]))
                    ec.sections.append((current[1], current[0]))
                elif "=" in line and current is not None:
                    k, v = line.split("=", 1)
                    current[0][k.strip().lower()] = v.strip().lower()
        return ec

    def properties_for(self, path: str) -> Dict[str, str]:
        props: Dict[str, str] = {}
        for patterns, values in self.sections:
            for p in patterns:
                # EditorConfig: patterns without "/" match the basename anywhere.
                target = path if "/" in p else os.path.basename(path)
                if glob_match(target, p.lstrip("/")):
                    props.update(values)
                    break
        return props


# --------------------------------------------------------------------------
# codesift config
# --------------------------------------------------------------------------

_CTX_KEYS = {
    "max-line-length": ("max_line_length", int),
    "indent-style": ("indent_style", str),
    "indent-size": ("indent_size", int),
    "quote-style": ("quote_style", str),
    "max-complexity": ("max_complexity", int),
    "max-function-length": ("max_function_length", int),
    "max-arguments": ("max_arguments", int),
}


@dataclass
class Override:
    paths: List[str]
    disable: List[str] = field(default_factory=list)
    settings: Dict[str, object] = field(default_factory=dict)


@dataclass
class Config:
    root: str
    include: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    disable: List[str] = field(default_factory=list)
    select: List[str] = field(default_factory=list)  # if set: only these rules/prefixes
    severity_overrides: Dict[str, Severity] = field(default_factory=dict)
    settings: Dict[str, object] = field(default_factory=dict)
    overrides: List[Override] = field(default_factory=list)
    fail_on: Severity = Severity.ERROR
    baseline: Optional[str] = None
    source: Optional[str] = None  # which file the config came from
    editorconfig: EditorConfig = field(default_factory=EditorConfig)

    # -- rule selection -----------------------------------------------------

    def rule_enabled(self, rule_id: str, rule_name: str, path: Optional[str] = None) -> bool:
        def matches(items):
            return any(rule_id.startswith(x) or rule_name == x for x in items)

        if self.select and not matches(self.select):
            return False
        if matches(self.disable):
            return False
        if path:
            for ov in self.overrides:
                if any(glob_match(path, p) for p in ov.paths) and matches(ov.disable):
                    return False
        return True

    def severity_for(self, rule_id: str, rule_name: str, default: Severity) -> Severity:
        return self.severity_overrides.get(rule_id) or self.severity_overrides.get(rule_name) or default

    def is_excluded(self, path: str) -> bool:
        if self.include and not any(glob_match(path, p) for p in self.include):
            return True
        return any(glob_match(path, p) for p in self.exclude)

    # -- per-file context ---------------------------------------------------

    def context_for(self, path: str) -> RuleContext:
        ctx = RuleContext()
        ec = self.editorconfig.properties_for(path)
        if ec.get("indent_style") in ("space", "tab"):
            ctx.indent_style = ec["indent_style"]
        if ec.get("indent_size", "").isdigit():
            ctx.indent_size = int(ec["indent_size"])
        if ec.get("max_line_length", "").isdigit():
            ctx.max_line_length = int(ec["max_line_length"])
        elif ec.get("max_line_length") == "off":
            ctx.max_line_length = 0
        if ec.get("insert_final_newline") == "false":
            ctx.insert_final_newline = False
        if ec.get("trim_trailing_whitespace") == "false":
            ctx.trim_trailing_whitespace = False
        if ec.get("quote_type") in ("single", "double"):
            ctx.quote_style = ec["quote_type"]

        settings = dict(self.settings)
        for ov in self.overrides:
            if any(glob_match(path, p) for p in ov.paths):
                settings.update(ov.settings)
        return _apply_settings(ctx, settings)


def _apply_settings(ctx: RuleContext, settings: Dict[str, object]) -> RuleContext:
    updates = {}
    for key, value in settings.items():
        if key in _CTX_KEYS:
            attr, typ = _CTX_KEYS[key]
            updates[attr] = None if value in ("auto", "none", None) else typ(value)
        else:
            ctx.options[key] = value
    return replace(ctx, **updates)


def _find_config_file(root: str) -> Optional[str]:
    for name in CONFIG_FILENAMES:
        p = os.path.join(root, name)
        if os.path.isfile(p):
            return p
    pyproject = os.path.join(root, "pyproject.toml")
    if os.path.isfile(pyproject) and tomllib is not None:
        with open(pyproject, "rb") as fh:
            try:
                data = tomllib.load(fh)
            except tomllib.TOMLDecodeError:
                return None
        if "codesift" in data.get("tool", {}):
            return pyproject
    return None


def load_config(root: str, path: Optional[str] = None) -> Config:
    root = os.path.abspath(root)
    cfg = Config(root=root, editorconfig=EditorConfig.load(root))
    path = path or _find_config_file(root)
    if not path:
        return cfg
    if tomllib is None:
        raise RuntimeError("Reading TOML config requires Python 3.11+ or the 'tomli' package.")
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    if os.path.basename(path) == "pyproject.toml":
        data = data.get("tool", {}).get("codesift", {})
    else:
        data = data.get("codesift", data)
    cfg.source = os.path.relpath(path, root)
    _merge(cfg, data)
    return cfg


def _merge(cfg: Config, data: dict) -> None:
    def as_list(v):
        return [v] if isinstance(v, str) else list(v or [])

    if "include" in data:
        cfg.include = as_list(data["include"])
    if "exclude" in data:
        cfg.exclude = list(DEFAULT_EXCLUDES) + as_list(data["exclude"])
    if "extend-exclude" in data:
        cfg.exclude += as_list(data["extend-exclude"])
    cfg.disable = as_list(data.get("disable", []))
    cfg.select = as_list(data.get("select", []))
    if "fail-on" in data:
        cfg.fail_on = Severity.parse(str(data["fail-on"]))
    if "baseline" in data:
        cfg.baseline = str(data["baseline"])
    for rid, sev in (data.get("severity") or {}).items():
        cfg.severity_overrides[rid] = Severity.parse(sev)
    for key in _CTX_KEYS:
        if key in data:
            cfg.settings[key] = data[key]
    for opt_key, value in (data.get("options") or {}).items():
        cfg.settings[opt_key] = value
    for ov in data.get("overrides", []) or []:
        settings = {k: v for k, v in ov.items() if k in _CTX_KEYS}
        cfg.overrides.append(Override(paths=as_list(ov.get("paths", [])),
                                      disable=as_list(ov.get("disable", [])),
                                      settings=settings))
