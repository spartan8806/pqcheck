# Operational scripts

All scripts are `#!/usr/bin/env bash` with `set -euo pipefail`, operate
only on local checkouts, and fail closed (non-zero, with the reason on
stderr) when their preconditions are not met.

| Script | What it does |
|---|---|
| [build_pqclean.sh](build_pqclean.sh) | Verifies PQClean at the pinned commit `0586a824…` (refusing any other), builds `harness_pqclean`, smoke-tests `info` for ML-KEM-512/768/1024. |
| [build_liboqs.sh](build_liboqs.sh) | Builds static OpenSSL-free liboqs, links `harness_liboqs`, smoke-tests the three ML-KEM sizes, prints the version to pin in the manifest. |
| [build_clib.sh](build_clib.sh) | Compiles the generic harness against `LIB_SRC`, smoke-tests `info` and the over-long-line `ERR` check. |
| [rebuild_harness.sh](rebuild_harness.sh) | Rebuilds one named harness binary from `pqcheck/adapters/`. |
| [break_mlkem.sh](break_mlkem.sh) | Positive control: plants a one-line FO bypass in your own clean local checkout (`BREAK_FILE`/`BREAK_AFTER`/`BREAK_INSERT`), proves pqcheck reports it, reverts via `trap`, rebuilds, and proves the clean build passes. Refuses a dirty tree. This script exists to keep the detector honest; it touches nothing outside the checkout you name. |

None of these scripts were executed in the pqcheck build environment
(no C compiler, no third-party checkouts there) — see DEVIATIONS.md.
They are shipped as operational tooling for a machine that has the
toolchains.
