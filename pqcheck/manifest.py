"""Declarative target manifests.

A manifest is untrusted data. Loading one never evaluates, imports,
or executes anything named by its fields: parsing is JSON plus the
strict schema in ``Manifest.__init__`` (unknown fields are refused,
every field is type- and shape-checked). Code is only ever loaded
later, when an operator explicitly runs that manifest through the
CLI's validated runner -- and even then adapters spawn argv arrays,
never a shell.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from pqcheck.verdict import Subject

ALLOWED_FIELDS = frozenset({
    "target", "version", "adapter", "algorithms", "harness",
    "node_cwd", "wsl", "padded", "kind", "oracle", "validation",
    "module", "command", "example",
})
_ALGORITHM_RE = re.compile(
    r"^(?:kem:|sig:)?[A-Za-z0-9][A-Za-z0-9._+\-]*"
    r"(?:\[[A-Za-z0-9._+\-]+\])?$")
_SAFE_TEXT_RE = re.compile(r"^[^\x00-\x1f;|&$`\"'<>\\]+$")

ADAPTERS: dict[str, dict] = {
    "c": {"required": ("harness",), "optional": ("wsl", "padded", "kind"), "algorithms": "required"},
    "noble": {"required": ("node_cwd",), "optional": ("padded",), "algorithms": "required"},
    "codec": {"required": ("harness",), "optional": ("oracle",), "algorithms": "forbidden"},
    "hint": {"required": ("harness",), "optional": ("oracle",), "algorithms": "forbidden"},
    "python": {"required": ("module",), "optional": (), "algorithms": "required"},
    "exec": {"required": ("command",), "optional": ("kind",), "algorithms": "required"},
}


class ManifestError(ValueError):
    """The manifest is invalid before any target is opened (exit 3)."""


@dataclass(frozen=True)
class AdapterSpec:
    name: str
    required: tuple[str, ...]
    optional: tuple[str, ...]
    algorithms: str


ADAPTER_SPECS = {k: AdapterSpec(k, tuple(v["required"]), tuple(v["optional"]), v["algorithms"]) for k, v in ADAPTERS.items()}


def _expand(value: str, base: Path) -> Path:
    expanded = os.path.expandvars(os.path.expanduser(value))
    p = Path(expanded)
    return p if p.is_absolute() else (base / p)


class Manifest:
    def __init__(self, data: dict, path: Path | None = None):
        if not isinstance(data, dict):
            raise ManifestError("manifest must be a JSON object")
        unknown = set(data) - ALLOWED_FIELDS
        if unknown:
            raise ManifestError(
                f"unknown manifest field(s): {sorted(unknown)}; "
                "manifests are untrusted data and are validated "
                "against a strict schema")
        for field_name, value in data.items():
            if isinstance(value, str) and "\x00" in value:
                raise ManifestError(
                    f"manifest field {field_name!r} contains a NUL byte")
        example = data.get("example", False)
        if not isinstance(example, bool):
            raise ManifestError("manifest field 'example' must be a boolean")
        self.example = example
        self.raw = dict(data)
        self.path = Path(path) if path else Path("manifest.json")
        self.base = self.path.parent
        for field in ("target", "version", "adapter"):
            if not isinstance(data.get(field), str) or not data[field].strip():
                raise ManifestError(f"manifest field {field!r} must be a non-empty string")
        self.target = data["target"]
        self.version = data["version"]
        self.adapter = data["adapter"]
        if self.adapter not in ADAPTERS:
            raise ManifestError(f"unknown adapter {self.adapter!r}; expected one of {sorted(ADAPTERS)}")
        try:
            Subject(target=self.target, commit=self.version)
        except ValueError as exc:
            raise ManifestError(str(exc)) from exc
        spec = ADAPTERS[self.adapter]
        for field in spec["required"]:
            if field not in data:
                raise ManifestError(f"adapter {self.adapter!r} requires manifest field {field!r}")
        algorithms = data.get("algorithms")
        if spec["algorithms"] == "required":
            if not isinstance(algorithms, list) or not algorithms or not all(isinstance(a, str) and a for a in algorithms):
                raise ManifestError(f"adapter {self.adapter!r} requires a non-empty 'algorithms' list")
            for entry in algorithms:
                if not _ALGORITHM_RE.match(entry):
                    raise ManifestError(
                        f"invalid algorithm name {entry!r}; expected "
                        "an optional kem:/sig: prefix followed by a "
                        "plain algorithm identifier")
            self.algorithms = tuple(algorithms)
        else:
            if algorithms:
                raise ManifestError(f"adapter {self.adapter!r} forbids 'algorithms'")
            self.algorithms = ()
        for flag in ("wsl", "padded"):
            value = data.get(flag, False)
            if not isinstance(value, bool):
                raise ManifestError(f"manifest field {flag!r} must be a boolean")
            setattr(self, flag, value)
        self.harness: Path | None = _expand(data["harness"], self.base) if isinstance(data.get("harness"), str) else None
        if "harness" in spec["required"] and self.harness is None:
            raise ManifestError("manifest field 'harness' must be a string path")
        self.node_cwd: Path | None = _expand(data["node_cwd"], self.base) if isinstance(data.get("node_cwd"), str) else None
        if "node_cwd" in spec["required"] and self.node_cwd is None:
            raise ManifestError("manifest field 'node_cwd' must be a string path")
        self.kind = data.get("kind")
        if self.kind is not None and self.kind not in ("kem", "sig"):
            raise ManifestError("manifest field 'kind' must be 'kem' or 'sig'")
        self.oracle = data.get("oracle")
        if self.oracle is not None and not (
                isinstance(self.oracle, str)
                and _SAFE_TEXT_RE.match(self.oracle)):
            raise ManifestError(
                "manifest field 'oracle' must be a plain label "
                "(no shell metacharacters or control characters)")
        for path_field in ("harness", "node_cwd", "module"):
            value = data.get(path_field)
            if value is not None and not (
                    isinstance(value, str) and value.strip()):
                raise ManifestError(
                    f"manifest field {path_field!r} must be a "
                    "non-empty string")
        # --- explicit API validation contract (Set 3, Phase 12) -----
        # FIPS 203 permits key checking earlier in a workflow, so who
        # validates raw serialized keys must be declared, not assumed.
        validation = data.get("validation")
        if validation is None:
            self.validation = {
                "standard": None, "key_format": None,
                "ek": "unspecified", "dk": "unspecified", "basis": None,
            }
        else:
            if not isinstance(validation, dict):
                raise ManifestError("manifest field 'validation' must be an object")
            allowed = {"validate-on-entry", "prevalidated-input", "unspecified"}
            parsed = {"standard": None, "key_format": None,
                      "ek": "unspecified", "dk": "unspecified", "basis": None}
            for key in ("ek", "dk"):
                value = validation.get(key, "unspecified")
                if not isinstance(value, str) or value not in allowed:
                    raise ManifestError(
                        f"validation.{key} must be one of {sorted(allowed)}, got {value!r}")
                parsed[key] = value
            for key in ("standard", "key_format", "basis"):
                value = validation.get(key)
                if value is not None and not (isinstance(value, str) and value.strip()):
                    raise ManifestError(f"validation.{key} must be a non-empty string")
                parsed[key] = value
            unknown = set(validation) - {"standard", "key_format", "ek", "dk", "basis"}
            if unknown:
                raise ManifestError(f"unknown validation field(s): {sorted(unknown)}")
            self.validation = parsed
        module = data.get("module")
        if "module" in spec["required"] and not (isinstance(module, str) and module.strip()):
            raise ManifestError("adapter 'python' requires manifest field 'module' (dotted name or file path)")
        self.module: str | None = module if isinstance(module, str) else None
        command = data.get("command")
        if "command" in spec["required"]:
            if not (isinstance(command, list) and command
                    and all(isinstance(c, str) and c for c in command)):
                raise ManifestError("adapter 'exec' requires manifest field 'command' (non-empty argv list)")
            _SHELLS = {"sh", "bash", "zsh", "dash", "cmd", "cmd.exe",
                       "powershell", "powershell.exe", "pwsh", "pwsh.exe"}
            import os as _os
            if _os.path.basename(command[0]).lower() in _SHELLS:
                raise ManifestError(
                    "adapter 'exec' command must be a harness argv, "
                    "not a shell interpreter; manifests never run "
                    "through a shell")
        self.command: list[str] | None = list(command) if isinstance(command, list) else None

    @classmethod
    def load(cls, path) -> "Manifest":
        p = Path(path)
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ManifestError(f"cannot read manifest {p}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ManifestError(f"manifest {p} is not valid JSON: {exc}") from exc
        return cls(data, p)

    def subject(self, algorithm=None, component=None) -> Subject:
        return Subject(target=self.target, commit=self.version, algorithm=algorithm, component=component)

    def with_overrides(self, overrides) -> "Manifest":
        data = dict(self.raw)
        for item in overrides or ():
            if "=" not in item:
                raise ManifestError(f"--set expects key=value, got {item!r}")
            key, value = item.split("=", 1)
            key, value = key.strip(), value.strip()
            if not key:
                raise ManifestError("--set key must be non-empty")
            if key == "algorithms":
                data[key] = [a.strip() for a in value.split(",") if a.strip()]
            elif value.lower() in ("true", "false"):
                data[key] = value.lower() == "true"
            else:
                data[key] = value
        return Manifest(data, self.path)

    def missing_paths(self) -> list[str]:
        problems = []
        if self.harness is not None and not self.harness.exists():
            problems.append(f"harness not found: {self.harness}")
        if self.node_cwd is not None and not self.node_cwd.exists():
            problems.append(f"node_cwd not found: {self.node_cwd}")
        if self.adapter == "python" and self.module and (
                self.module.endswith(".py") or "/" in self.module or "\\" in self.module):
            module_path = _expand(self.module, self.base)
            if not module_path.exists():
                problems.append(f"python module file not found: {module_path}")
        return problems

    def wrong_version(self) -> str | None:
        if self.adapter != "noble" or self.node_cwd is None:
            return None
        candidates = [
            self.node_cwd / "node_modules" / "@noble" / "post-quantum" / "package.json",
            self.node_cwd / "package.json",
        ]
        for pkg_path in candidates:
            if not pkg_path.exists():
                continue
            try:
                pkg = json.loads(pkg_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            installed = str(pkg.get("version", "")).lstrip("v")
            if pkg_path.name == "package.json" and pkg.get("name") != "@noble/post-quantum" and "node_modules" not in str(pkg_path):
                deps = {**(pkg.get("dependencies") or {}), **(pkg.get("devDependencies") or {})}
                wanted = deps.get("@noble/post-quantum")
                if not wanted:
                    continue
                installed = str(wanted).lstrip("^~v ")
                if installed != self.version.lstrip("v"):
                    return f"manifest version {self.version} but package.json requires @noble/post-quantum {wanted}"
                return None
            if installed and installed != self.version.lstrip("v"):
                return f"manifest version {self.version} but installed @noble/post-quantum is {installed}"
            return None
        return None
