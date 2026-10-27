# Standing regression probes

`python -m pqcheck.probes` runs every `verify_*.py` here and classifies
each by exit code:

| Exit | Meaning |
|---|---|
| `0` | verified |
| `77` | skipped — the probe must print a line starting with `SKIP:` saying what is absent |
| `78` | partial |
| other | failure |

Rules:

- A probe that prints a line starting with `SKIP` while exiting `0` is a
  protocol violation and fails the whole run. Skipping is honest only at
  exit `77`, with a reason.
- Core probes are pure Python and must pass everywhere. They check both
  directions where applicable: silence on correct targets, and detection
  on planted mutants (a probe that only ever passes is not a probe).
- Conditional probes (`verify_snova*`, `verify_stateful_gate`,
  `verify_codec_oracle`, `verify_roundtrip_order`, `verify_hint_oracle`,
  also listed in `pqcheck.probes.CONDITIONAL`) need an external harness
  binary and exit `77` when it is not on disk.
- Probes are standalone: `python probes/verify_crash.py` works on its own
  and prints what it tested. Shared fakes live in `probe_lib.py`, which is
  not a probe and is never run by the runner.
- Naming that differs from a library's internal vocabulary is adapted to
  pqcheck's Set 1 API (e.g. `ClaimError`, `reproduce`, `observed`), never
  the other way round: the probes serve the engine, not vice versa.
