"""Declarative target manifests."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from pqcheck.verdict import Subject

ADAPTERS: dict[str, dict] = {
    "c": {"required": ("harness",), "optional": ("wsl", "padded", "kind"), "algorithms": "required"},
    "noble": {"required": ("node_cwd",), "optional": ("padded",), "algorithms": "required"},
    "codec": {"required": ("harness",), "optional": ("oracle",), "algorithms": "forbidden"},
    "hint": {"required": ("harness",), "optional": ("oracle",), "algorithms": "forbidden"},
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
        self.oracle = data.get("oracle")

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
