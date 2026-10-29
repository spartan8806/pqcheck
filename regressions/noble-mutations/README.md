# Noble mutation regression kit (Set 3, Phase 13)

Reproducible real-code regression kit imported from the independent
mutation audit (`D:\pqcheck-mutation-audit-20261028`, treated
read-only). It closes the three gaps that campaign found and keeps
the ten previously detected mutations under continuous regression.

## Pins

- Upstream: `paulmillr/noble-post-quantum` **0.6.1** at
  `99da15c1a5417f5c3fc36e7d84e7525fdcdbeaa9`.
- Pinned built-JavaScript SHA-256 (verified before any run):
  `ml-kem.js` `c008845a…`, `ml-dsa.js` `210a020b…`, `utils.js`
  `b3d97248…` (full values in [noble-mutations.json](noble-mutations.json)).
- Dependencies: the checkout's own `node_modules/@noble/{hashes,curves,ciphers}`.

## Layout

- [noble-mutations.json](noble-mutations.json) — case inventory:
  baseline, 10 `should-detect` mutations, 4 `newly-covered` cases
  (the 3 audit misses plus an additional 8,192-byte truncation
  control), and 2 contract controls. Each mutation is an isolated,
  exactly-counted replacement against the pinned built JavaScript
  (what the Noble adapter executes). Detection logic never reads
  this file, case names, or directory names.
- [run_kit.py](run_kit.py) — executor. For each case it builds an
  isolated mutated copy, writes a normal pqcheck manifest
  (`validate-on-entry` declared for KEM cases), runs pqcheck in a
  fresh process, asserts the expected relations from the JSON
  report, generates reproducers for defect cases, and replays them.
  A replay counts only when the script exits 1 AND its stdout is a
  valid JSON report naming that script's relation `DEFECT_FOUND`;
  an exit code alone (e.g. a script crashing before testing
  anything) proves nothing. Replay stdout/stderr are preserved
  beside each script. Defect cases must pair their defect report
  with exit exactly 1; clean and contract controls must have zero
  findings and exit 0.

## Run

```powershell
python regressions/noble-mutations/run_kit.py --src D:\path\to\noble-post-quantum --seed 1
python regressions/noble-mutations/run_kit.py --src D:\path\to\noble-post-quantum --cases explore-kem-ek-modulus-check-removed --seed 2
```

- Exit 0: every expectation met. Exit 1: expectation mismatch.
  Exit 2: prerequisite missing/mismatched or a mutation anchor did
  not occur the stated number of times (the kit refuses to guess).
- An ordinary pqcheck run against a manifest whose `node_cwd` is
  absent already explains the missing prerequisite through verdict
  semantics (`NOT_REACHED`); the kit's exit 2 is the CI gate form.

## Expected results (seed-independent in practice; verified seeds 1–3)

| Case | Expected |
| --- | --- |
| baseline | no `DEFECT_FOUND`, exit 0 |
| 10 `should-detect` | each expected relation `DEFECT_FOUND` |
| explore-kem-ek-modulus-check-removed | `kem-ek-rejects-noncanonical` |
| explore-kem-dk-hash-check-removed | `kem-dk-rejects-hash-mismatch` |
| explore-sig-long-message-truncation (4096) | `sig-message-binding` |
| control-sig-truncation-8192 | `sig-message-binding` |
| control-contract-prevalidated / -unspecified | both new KEM relations `NOT_ANSWERABLE`, no defect |

## CI

The `noble-kit` job in `.github/workflows/ci.yml` clones the pinned
revision, installs/builds it, and runs the full kit across seeds
1–3. A missing prerequisite fails that job (exit 2), as required.

## Limitations

- Mutations patch the built JavaScript, not the TypeScript source;
  anchors are hash- and count-pinned to the 0.6.1 build.
- The kit covers ML-KEM-768 and ML-DSA-44 mutation targets (the
  audit's targets). All three ML-KEM parameter sets are covered by
  the unit/self-test toys and the Noble full fixture.
- Contract controls exercise the manifest declaration path only;
  the declaration is recorded as declared, never presented as
  independently proven.
