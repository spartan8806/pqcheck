# START: a stranger's walkthrough

You need Python 3.10+ and nothing else: pqcheck has zero third-party
dependencies. All commands run from the repository root.

## 1. The tool tests itself first

```sh
python -m pqcheck.selftest
```

Expected tail: `selftest: ok (0 false positives, all mutants live and
caught, seed gate holds)`. This runs all 32 relations against clean
reference toys (expecting no defect) and against 41 planted mutants
(expecting every mutant to be caught and every relation to fire at
least once). For a seed sweep:

```sh
python -m pqcheck.selftest --seeds 10
```

Each of the 10 deterministic seeds must show 100% precision and
100% recall, with zero seed-dependent flakiness.

```sh
python -m pqcheck.verdict
```

Expected: `verdict self-check: ok`. This exercises the honesty gates:
clean claims without coverage, defects without reproducers, plain-string
verdicts, moving version references, and secret-shaped report text are
all refused at construction time.

## 2. The four-act demo

```sh
python -m pqcheck demo
```

Act 1 runs all 32 relations on clean and boundary targets (0 defects,
honest declines). Act 2 catches four flagship mutants with printed
witnesses. Act 3 shows a completely broken signer still producing a
loud `DEFECT_FOUND`. Act 4 shows `Report.score()` and the secret-material
floor refusing. It finishes in a few seconds and needs no target.

## 3. Point it at a real library

Shipped manifests live in [manifests/](../manifests/README.md):

- [manifests/noble.json](../manifests/noble.json) — @noble/post-quantum
  via the Node bridge (`node_cwd` must point at your install).
- [manifests/pqclean.json](../manifests/pqclean.json) — PQClean via the
  C harness (build with [tools/build_pqclean.sh](../tools/build_pqclean.sh)).
- [manifests/liboqs.json](../manifests/liboqs.json) — liboqs via the C
  harness (build with [tools/build_liboqs.sh](../tools/build_liboqs.sh)).

```sh
python -m pqcheck run manifests/noble.json
python -m pqcheck run manifests/noble.json --relation kem-fo-liveness
python -m pqcheck reproduce manifests/noble.json --relation kem-fo-liveness
```

Targets are only ever opened through a local manifest or an explicitly
named local folder. There is no network mode and no remote target.

## 4. Reading the exit code

| Exit | Meaning |
| --- | --- |
| 0 | Clean and conclusive somewhere: no defect, at least one real check ran. |
| 1 | A defect was found (or, for `selftest`/`demo`, the showcase itself failed). |
| 2 | The run established nothing (everything declined or was not reached). |
| 3 | Bad CLI usage or a bad manifest. Exit 3 is never a verdict on a target. |

`NOT_REACHED` and `NOT_ANSWERABLE` are never counted as clean. A run
that establishes nothing says so, in words, at the top of its report.

## 5. Where to go next

- The assurance model: [00_SPEC_pqc_assurance.md](00_SPEC_pqc_assurance.md)
- Every relation: [01_SPEC_relations.md](01_SPEC_relations.md)
- What the tool cannot see: [06_LIMITATIONS.md](06_LIMITATIONS.md)
