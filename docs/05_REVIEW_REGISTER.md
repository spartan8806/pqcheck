# 05 — Review register: adversarial findings and their locks

Each row: a finding from adversarial review of pqcheck itself, the
fix, and the standing probe ([probes/](../probes/)) that keeps it
closed. Probes follow the exit protocol in
[pqcheck/probes.py](../pqcheck/probes.py): 0 pass, 77 skipped
(conditional, reason printed), 78 partial; a SKIP line with exit 0
is a protocol failure. Run them all with `python -m pqcheck.probes`.

| # | Finding | Lock |
| --- | --- | --- |
| R1 | Clean claim constructible with empty coverage (unearned reassurance) | [verify_unearned_claim_gates.py](../probes/verify_unearned_claim_gates.py), [verify_verdict.py](../probes/verify_verdict.py) |
| R2 | Defect claim constructible with a stub reproducer | [verify_unearned_claim_gates.py](../probes/verify_unearned_claim_gates.py) |
| R3 | Plain-string verdict bypassing the enum gates | [verify_claim_type_gate.py](../probes/verify_claim_type_gate.py) |
| R4 | Secret-shaped material pastable into a public report | [verify_no_key_material.py](../probes/verify_no_key_material.py) |
| R5 | Target crash misattributed to the current relation (post-mortem repeats) | [verify_crash_attrib.py](../probes/verify_crash_attrib.py), [verify_adapter_death_contract.py](../probes/verify_adapter_death_contract.py) |
| R6 | pqcheck's own deadline kill reported as a target defect | [verify_deadline_attribution.py](../probes/verify_deadline_attribution.py) |
| R7 | Single uncorroborated fault upgraded to a defect | [verify_crash.py](../probes/verify_crash.py), [verify_assertion_partition.py](../probes/verify_assertion_partition.py) |
| R8 | Relation claims coverage with zero observed target calls | [verify_coverage_measured.py](../probes/verify_coverage_measured.py), [verify_crash_and_zeroobs.py](../probes/verify_crash_and_zeroobs.py) |
| R9 | Positive-control failure silently read as clean | [verify_probe_control.py](../probes/verify_probe_control.py), [verify_relations.py](../probes/verify_relations.py) |
| R10 | Constructed-probe layout assumed but never validated (wrong-layout false defects) | [verify_probe_control.py](../probes/verify_probe_control.py) |
| R11 | 12-bit `ek` codec endianness shared between relation and toy (self-consistent, wrong) | unit test `test_toy_bitpacker_is_independent_and_agrees` in [tests/test_backtest_probes.py](../tests/test_backtest_probes.py); toy uses `_bitpack12`/`_bitunpack12`, relation uses `_pack12`/`_unpack12` |
| R12 | Backtest grades summed into a single "COVERED" number | [verify_registry_backtest.py](../probes/verify_registry_backtest.py) asserts per-grade counts and no `COVERED` key |
| R13 | SKIP printed with exit 0 (dishonest skip) | unit tests in [tests/test_backtest_probes.py](../tests/test_backtest_probes.py) against `_classify` in [pqcheck/probes.py](../pqcheck/probes.py) |
| R14 | `ek` mutation touching the 32-byte `rho` tail instead of coefficients | [verify_probe_control.py](../probes/verify_probe_control.py) plus the Noble 0.6.1 regression fixture in [pqcheck/testing/fixtures.py](../pqcheck/testing/fixtures.py) |
| R15 | One-sided FO result counted as clean in UI/report | [verify_ui_honesty.py](../probes/verify_ui_honesty.py), [verify_report_text.py](../probes/verify_report_text.py) |
| R16 | Discovery executing a found binary, or guessing its version | [verify_discovery.py](../probes/verify_discovery.py) |
| R17 | Unopenable real target producing a traceback instead of 32 honest declines | [verify_unopened_target_noble.py](../probes/verify_unopened_target_noble.py) |
| R18 | Variable-length signature forced through fixed-length relations | [verify_varlen.py](../probes/verify_varlen.py) |
| R19 | Oracle use hidden from the report reader | [verify_oracle_disclosure.py](../probes/verify_oracle_disclosure.py) |
| R20 | Premises smuggled as a bare string | [verify_premises.py](../probes/verify_premises.py) |
| R21 | Documentation paths and README numbers rotting silently | [verify_paths_resolve.py](../probes/verify_paths_resolve.py), [verify_readme_claims.py](../probes/verify_readme_claims.py) |
| R22 | Shipped manifests drifting from their pinned versions | [verify_shipped_manifests.py](../probes/verify_shipped_manifests.py) |
| R23 | Report text breaking under non-UTF-8 terminal encodings | [verify_report_encoding.py](../probes/verify_report_encoding.py) |
| R24 | Reproducer scripts that do not round-trip to the same verdict | [verify_reproducer_roundtrip.py](../probes/verify_reproducer_roundtrip.py) |

Conditional probes (exit 77 when the optional binary is absent):
[verify_snova.py](../probes/verify_snova.py),
[verify_snova_count.py](../probes/verify_snova_count.py),
[verify_stateful_gate.py](../probes/verify_stateful_gate.py),
[verify_codec_oracle.py](../probes/verify_codec_oracle.py),
[verify_roundtrip_order.py](../probes/verify_roundtrip_order.py),
[verify_hint_oracle.py](../probes/verify_hint_oracle.py).
A conditional probe that cannot run says why and exits 77; it never
prints SKIP and exits 0 (R13).
