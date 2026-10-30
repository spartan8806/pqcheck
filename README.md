# pqcheck

Zero-dependency Python 3.10+ assurance and property-testing tool for
post-quantum cryptographic (PQC) implementations: KEMs, digital signatures,
and wire-format codecs.

Instead of known-answer tests, pqcheck checks **metamorphic relations and
specification invariants** — FO implicit-rejection binding and liveness,
encoding canonicality, declared-length wrap boundaries, guard-fill
bit-exclusion, hint ordering — that must hold whatever the exact output
bytes are.

## Structural honesty

Every check produces a `Claim` with one of four verdicts. There is no
`PASS`:

| Verdict | Meaning |
|---|---|
| `DEFECT_FOUND` | The property was tested and violated, or a corroborated target-attributable fault/hang occurred. |
| `NO_DEFECT_FOUND` | The property was tested against the target (runner-observed calls > 0) and did not fire. |
| `NOT_REACHED` | The check could not exercise the target. Never counted as clean. |
| `NOT_ANSWERABLE` | The check does not apply to this target's API or geometry. |

Unearned reassurance is unconstructible: claim constructors refuse empty
coverage on clean claims, stub reproducers on defects, moving version
references (`main`, `latest`, …), plain-string verdicts, and secret-shaped
material in report text. There is no score, grade, or percentage:
`Report.score()` raises `NotImplementedError` by design.

Exit codes: `0` clean and conclusive, `1` defect found, `2` the run
established nothing, `3` bad CLI/manifest.

## Quick start

```sh
python -m pqcheck relations          # the 34 registered relations
python -m pqcheck adapters           # manifest adapters
python -m pqcheck.selftest           # toys + mutants acceptance suite
python -m pqcheck.testing.precision  # adversarial precision boundary suite
python -m pqcheck.backtest.report    # historical defect-class accounting
python -m pqcheck.probes             # standing regression probes (probes/)
```

Shipped manifests (PQClean, liboqs, Noble, a Falcon codec, the enc_rust vulnerable/fixed pair, a Python reference, a C-library template) live in
[manifests/](manifests/), with build scripts in [tools/](tools/). A reproducible Noble 0.6.1 mutation regression kit lives in [regressions/noble-mutations/](regressions/noble-mutations/).
Constant-time and timing instruments (Valgrind secret-poisoning triage,
Welch's t-test timing) are in [pqcheck/adapters/](pqcheck/adapters/) —
they report leads and bounds, never certificates. See
[SECURITY.md](SECURITY.md) for how to report a defect (including false
reassurance, which is a security bug in this tool).

Run against a real target by writing a manifest (see
[manifests/noble.json](manifests/noble.json) and
[manifests/c-library.json](manifests/c-library.json)):

```sh
python -m pqcheck run path/to/manifest.json --seed 00ff
python -m pqcheck run path/to/folder          # zero-execution discovery
python -m pqcheck reproduce manifest.json --relation kem-fo-liveness
python -m pqcheck run manifest.json --json --reproducers out/
python -m pqcheck ui path/to/folder
```

Targets are only ever opened through a local manifest or an explicitly
named local folder. Discovery never executes a binary it finds; a compiled
harness whose version cannot be stated is reported as missing its version
rather than guessed.

## Layout

- [pqcheck/verdict.py](pqcheck/verdict.py) — verdict/claim/report engine
- [pqcheck/target.py](pqcheck/target.py) — target seam and process-death attribution
- [pqcheck/relations/](pqcheck/relations/) — the 34 relations and the runner
- [pqcheck/ai.py](pqcheck/ai.py) — Muse AI Expansion Engine (opt-in, clean-control gated)
- [pqcheck/adapters/](pqcheck/adapters/) — C harness, Noble (JS), codec and hint bridges
- [pqcheck/testing/](pqcheck/testing/) — reference toys, planted mutants, precision fixtures
- [pqcheck/backtest/](pqcheck/backtest/) — historical defect-class corpus and accounting
- [probes/](probes/) — standing regression probes (`verify_*.py`)

## Muse AI expansion (opt-in)

Without a key, pqcheck is the deterministic core above and prints
`Muse AI expansion: INACTIVE (34 deterministic relations ran at 0 tokens; ...)`.
With `--muse` (live, needs `MUSE_API_KEY`/`MUSE_API_BASE`), or
`--muse-simulate` (offline simulated client), the core report is
summarized into a compact GapDigest and Muse may propose candidate
probes for uncovered surfaces. Muse never emits an unverified
finding: every candidate runs in a wiped ephemeral temp directory,
must not fire on a clean reference fixture (Clean-Reference
Precision Gate), runs against the target under crash-watching, and
must pass the secret-material floor. Results land in the report's
`ai_receipt` (text, JSON, and HTML). The demo's Act 5
(`python -m pqcheck demo`) shows the whole pipeline offline.

## Safety scope

pqcheck is a defensive assurance tool. It only talks to targets the
operator points it at locally, through declarative manifests. Reports are
designed to be pasted into public bug trackers: secret-shaped material is
refused in claims and redacted from quoted target output.

## Source checkout vs installed wheel

From a source checkout, everything in this README works as written, including `python -m pqcheck.probes` (the standing probes in `probes/`) and the shipped manifests in `manifests/`. In an installed wheel, the same probes and example manifests ship inside the package as bundled assets (`pqcheck/assets/probes` and `pqcheck/assets/manifests`), and `python -m pqcheck.probes` finds them there; to locate the bundled manifests on disk: `python -c "import pqcheck, pathlib; print(pathlib.Path(pqcheck.__file__).parent / 'assets' / 'manifests')"`. The bundled copies are byte-identical to the checkout files (a unit test enforces this). Building real C/Rust/Java harnesses still requires a source checkout and a toolchain.
