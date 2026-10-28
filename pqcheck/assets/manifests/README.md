# Shipped manifests

Declarative targets for `pqcheck run`. A manifest names the target, an
exact version (a commit or release — moving references such as `main`
are refused), the adapter, and where the local harness or Node tree is.

| Manifest | Target | Build it with |
|---|---|---|
| [noble.json](noble.json) | `@noble/post-quantum` 0.6.1 via Node | set `NOBLE_DIR` to a checkout with the package installed |
| [pqclean.json](pqclean.json) | PQClean ML-KEM (clean trees) | [tools/build_pqclean.sh](../tools/build_pqclean.sh) |
| [liboqs.json](liboqs.json) | liboqs ML-KEM | [tools/build_liboqs.sh](../tools/build_liboqs.sh) |
| [falcon-codec.json](falcon-codec.json) | Falcon `comp_encode`/`comp_decode` codec | [pqcheck/adapters/falcon_compdecode_fixture.sh](../pqcheck/adapters/falcon_compdecode_fixture.sh) |
| [c-library.json](c-library.json) | template for your own C library | [tools/build_clib.sh](../tools/build_clib.sh) |
| [python-reference.json](python-reference.json) | pqcheck reference toys (`python` adapter) | nothing — runs out of the box with no compiler or Node |

Algorithms may carry a kind prefix (`kem:ML-KEM-768`, `sig:ML-DSA-65`)
so one harness binary can serve both kinds. Relative harness paths
resolve against the manifest's own directory, `~` and `${ENV}` expand.

While a harness is unbuilt, every build-requiring manifest here exits `2`
(established nothing) — never `0`. A shipped manifest must never be able
to report a clean result for a target that was never opened. The
exception is `python-reference.json`: the `python` adapter needs no
build, so it runs conclusively (exit `0`) on any machine.
