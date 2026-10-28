"""PythonTarget loader: drive an in-process Python target class.

A manifest with "adapter": "python" names a module (dotted import path
or a .py file path) and, per algorithm entry, a target class in that
module: "PackedEkKem", "class:PackedEkKem", or "PackedEkKem[mutant]".
The instantiated object is used directly as the pqcheck target.
"""
from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path

from pqcheck.target import HarnessProtocolError


def _load_module(module_spec: str, base: Path):
    if module_spec.endswith(".py") or "/" in module_spec or "\\" in module_spec:
        path = Path(module_spec)
        if not path.is_absolute():
            path = (base / path).resolve()
        if not path.exists():
            raise HarnessProtocolError(f"python module file not found: {path}")
        name = f"pqcheck_user_target_{path.stem}"
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise HarnessProtocolError(f"cannot load python module: {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module
    try:
        return importlib.import_module(module_spec)
    except ImportError as exc:
        raise HarnessProtocolError(f"cannot import python module {module_spec!r}: {exc}") from exc


def load_python_target(module_spec: str, algorithm: str, base: Path):
    """Instantiate the target class named by an algorithm entry."""
    entry = algorithm.strip()
    if entry.startswith("class:"):
        entry = entry[len("class:"):]
    mutant = None
    if entry.endswith("]") and "[" in entry:
        entry, mutant = entry[:-1].split("[", 1)
    module = _load_module(module_spec, base)
    cls = getattr(module, entry, None)
    if cls is None or not isinstance(cls, type):
        raise HarnessProtocolError(
            f"module {module_spec!r} has no target class {entry!r}")
    try:
        return cls(mutant=mutant) if mutant else cls()
    except TypeError as exc:
        raise HarnessProtocolError(
            f"target class {entry!r} could not be instantiated: {exc}") from exc


# exec adapter: any argv command speaking the line protocol. The argv
# receives "<kind> <algorithm>" appended, exactly like a C harness.
def load_exec_target(command, kind: str, algorithm: str):
    from pqcheck.adapters.cbridge import CTarget
    return CTarget(list(command), kind, algorithm)
