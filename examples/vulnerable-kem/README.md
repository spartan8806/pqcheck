# vulnerable-kem: a sample project with a defect that pops

This is a test project for pqcheck itself. The little KEM in
`vulnkem.py` has a planted defect: decapsulation never checks the
ciphertext tag, so edited ciphertexts decapsulate to the honest
shared secret (a Fujisaki–Okamoto liveness failure). pqcheck
**will** find it. Do not use this code for anything real.

## See it pop (CLI)

```sh
python -m pqcheck run examples/vulnerable-kem/manifest.json
echo "exit=$?"   # expect 1: DEFECT_FOUND
python -m pqcheck reproduce examples/vulnerable-kem/manifest.json --relation kem-fo-liveness
```

## See it pop (workbench)

```sh
python -m pqcheck web --port 8420
```

Open http://127.0.0.1:8420/, and in the Project tab open this
folder (`examples/vulnerable-kem`). Readiness should pass, Run
checks should produce Findings, and the reproduction export will
contain the exact `pqcheck reproduce` commands.

## The fix (for contrast)

Decapsulation would recompute the tag over the recovered `r` and
reject on mismatch — the check `vulnkem.decaps` skips. The relations
that catch the defect (`kem-fo-liveness`,
`kem-reject-ct-bit-contribution`, …) are witness searches: if a
future version of this sample stopped producing witnesses, those
checks would read *Inconclusive*, not "secure" — one-sided results
never count as a pass in pqcheck.
