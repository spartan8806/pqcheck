# pqcheck documentation

Reading order for a technical reviewer:

1. [START.md](START.md) — a stranger's hands-on walkthrough. Run the
   commands; watch the exit codes.
2. [00_SPEC_pqc_assurance.md](00_SPEC_pqc_assurance.md) — the formal
   assurance model: verdicts, epistemic refusal rules, failure taxonomy.
3. [01_SPEC_relations.md](01_SPEC_relations.md) — all 34 relations:
   properties, controls, capabilities, ceilings, false-positive modes.
4. [02_VALIDATION.md](02_VALIDATION.md) — how precision and recall are
   validated (toy targets, 43 planted mutants, boundary targets, seeds).
5. [03_RESOLVED_fo_liveness.md](03_RESOLVED_fo_liveness.md) — the
   FO-liveness deep-dive: decryption fibers, compression witnesses, and
   how a dead FO check is separated from encoding slack.
6. [04_BACKTEST.md](04_BACKTEST.md) — historical-defect backtest,
   generated from the backtest report command, with the ours-vs-theirs
   analysis and the work queue.
7. [05_REVIEW_REGISTER.md](05_REVIEW_REGISTER.md) — adversarial review
   findings and the standing probes that lock each one closed.
8. [06_LIMITATIONS.md](06_LIMITATIONS.md) — what pqcheck cannot see.
9. [REFERENCES.md](REFERENCES.md) — standards and defect citations.

Conventions: every repository path in these documents is checked by
[probes/verify_paths_resolve.py](../probes/verify_paths_resolve.py), and
every quantitative claim in the README files is checked by
[probes/verify_readme_claims.py](../probes/verify_readme_claims.py).
If a path or a number rots, a probe fails.
