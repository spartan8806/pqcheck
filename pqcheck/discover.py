"""Zero-execution folder discovery: find candidate targets without running them."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from pqcheck.manifest import Manifest, ManifestError

_MAX_DEPTH = 5
_SKIP_DIRS = {".git", ".hg", ".sl", ".eden", "__pycache__", ".venv", "venv", ".mypy_cache", ".pytest_cache"}
_MAGICS = (
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE"),
    (b"\xfe\xed\xfa\xce", "Mach-O"),
    (b"\xfe\xed\xfa\xcf", "Mach-O"),
    (b"\xce\xfa\xed\xfe", "Mach-O"),
    (b"\xcf\xfa\xed\xfe", "Mach-O"),
    (b"\xca\xfe\xba\xbe", "Mach-O"),
)


@dataclass
class Candidate:
    kind: str
    path: Path
    ready: bool = False
    missing: tuple[str, ...] = ()
    detail: str = ""
    manifest: Manifest | None = field(default=None, repr=False)
    algorithms: tuple[str, ...] = ()


def _magic_kind(path: Path) -> str | None:
    try:
        with path.open("rb") as fh:
            head = fh.read(4)
    except OSError:
        return None
    for magic, name in _MAGICS:
        if head.startswith(magic):
            return name
    return None


def _is_build_intermediate(path: Path) -> bool:
    parts = {p.lower() for p in path.parts}
    name = path.name.lower()
    return (
        "build-script" in name or "build_script" in name
        or "incremental" in parts
        or (("deps" in parts) and name.startswith("build_script"))
    )


def _noble_candidate(node_root: Path) -> Candidate | None:
    pkg_path = node_root / "node_modules" / "@noble" / "post-quantum" / "package.json"
    if not pkg_path.exists():
        return None
    version = None
    try:
        version = json.loads(pkg_path.read_text(encoding="utf-8")).get("version")
    except (OSError, json.JSONDecodeError):
        pass
    missing = () if version else ("version",)
    return Candidate(
        kind="noble", path=node_root, ready=bool(version),
        missing=missing,
        detail=f"@noble/post-quantum {version}" if version else "@noble/post-quantum (version unreadable)",
    )


def discover(folder) -> list[Candidate]:
    root = Path(folder)
    candidates: list[Candidate] = []
    if not root.is_dir():
        return candidates
    noble = _noble_candidate(root)
    if noble:
        candidates.append(noble)

    def walk(directory: Path, depth: int):
        if depth > _MAX_DEPTH:
            return
        try:
            entries = sorted(directory.iterdir(), key=lambda p: p.name.lower())
        except OSError:
            return
        for entry in entries:
            if entry.is_symlink() and entry.is_dir():
                # Never follow directory symlinks out of the scanned
                # folder: a linked directory could walk the whole
                # filesystem beyond the operator-named root.
                continue
            if entry.is_dir():
                if entry.name in _SKIP_DIRS:
                    continue
                if entry.name == "node_modules":
                    found = _noble_candidate(directory)
                    if found and found not in candidates:
                        candidates.append(found)
                    continue
                if (entry / "CMakeLists.txt").exists() or (entry / "Cargo.toml").exists():
                    candidates.append(Candidate(
                        kind="source", path=entry, ready=False,
                        missing=("needs_build",),
                        detail="unbuilt source tree; build a pqcheck harness against it first (see pqcheck/adapters/c_harness.c)",
                    ))
                walk(entry, depth + 1)
            elif entry.is_file():
                if entry.suffix.lower() == ".json":
                    try:
                        manifest = Manifest.load(entry)
                    except ManifestError:
                        continue
                    problems = manifest.missing_paths()
                    candidates.append(Candidate(
                        kind="manifest", path=entry, ready=not problems,
                        missing=tuple(problems), manifest=manifest,
                        algorithms=manifest.algorithms,
                        detail=f"{manifest.target} via {manifest.adapter}",
                    ))
                    continue
                magic = _magic_kind(entry)
                if magic and not _is_build_intermediate(entry):
                    candidates.append(Candidate(
                        kind="harness", path=entry, ready=False,
                        missing=("version", "algorithms"),
                        detail=f"compiled {magic} harness binary; a binary cannot state which commit it was built from",
                    ))

    walk(root, 0)
    seen: set[tuple[str, str]] = set()
    unique: list[Candidate] = []
    for c in candidates:
        key = (c.kind, str(c.path).lower())
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique
