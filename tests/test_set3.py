"""Set 3 (Phases 11-12): long-message binding, truncation mutants,
explicit ML-KEM validation contract, and the two strict relations."""
import random
import unittest

from pqcheck.manifest import Manifest, ManifestError
from pqcheck.relations.base import REGISTRY
from pqcheck.relations.sig_generic import MessageBinding
from pqcheck.testing.toy import ToySig
from pqcheck.testing.toylwe import PackedEkKem
from pqcheck.verdict import Subject, Verdict

SUBJ = Subject(target="set3-test", commit="0123456789abcdef0123456789abcdef01234567")


def run(rid, target, seed=7):
    return REGISTRY[rid].run(target, SUBJ, random.Random(seed))


def noble_manifest(validation=None):
    data = {"target": "t", "version": "0.6.1", "adapter": "noble",
            "node_cwd": ".", "algorithms": ["ml-kem-768"]}
    if validation is not None:
        data["validation"] = validation
    return Manifest(data)


class MessageBindingLengthTests(unittest.TestCase):
    def test_bounds_match_spec(self):
        self.assertEqual(MessageBinding.BOUNDARIES, (256, 512, 1024, 4096, 65536))
        self.assertEqual(MessageBinding.MAX_MESSAGE, 65537)
        self.assertEqual(MessageBinding.MAX_ATTEMPTS, 1024)

    def test_clean_toy_no_defect(self):
        claim = run("sig-message-binding", ToySig())
        self.assertIs(claim.verdict, Verdict.NO_DEFECT_FOUND, claim.evidence)

    def test_truncation_4096_detected(self):
        claim = run("sig-message-binding", ToySig(mutant="msg_truncates_at_4096"))
        self.assertIs(claim.verdict, Verdict.DEFECT_FOUND, claim.evidence)
        self.assertIn("4096", claim.evidence + claim.reproduce)

    def test_truncation_8192_detected(self):
        claim = run("sig-message-binding", ToySig(mutant="msg_truncates_at_8192"))
        self.assertIs(claim.verdict, Verdict.DEFECT_FOUND, claim.evidence)
        # the accepted edit must be past the 8192 cutoff
        import re
        offset = int(re.search(r"byte offset (\d+)", claim.evidence).group(1))
        self.assertGreater(offset, 8192, claim.evidence)

    def test_short_message_mutants_still_detected(self):
        for mutant in ("msg_unbound", "msg_prefix_only"):
            claim = run("sig-message-binding", ToySig(mutant=mutant))
            self.assertIs(claim.verdict, Verdict.DEFECT_FOUND, (mutant, claim.evidence))


class _RandomizedSig(ToySig):
    """Hedged-style signer declaring PINNED_RANDOMNESS (its keygen is
    seed-deterministic, like the Noble bridge reports) while signing
    produces a different valid signature on every call."""

    def __init__(self):
        super().__init__()
        self._counter = 0

    def sign(self, sk, msg, ctx=b"", prehash=False, declared_len=None):
        from pqcheck.testing.toy import _h, _ok
        self._counter += 1
        salt = self._counter.to_bytes(16, "big")
        pk = _h(b"pk", bytes(sk))
        return _ok(salt + _h(b"rsig", pk, bytes(msg), salt, out=48))

    def verify(self, pk, msg, sig, ctx=b"", prehash=False, declared_len=None):
        from pqcheck.testing.toy import _h, _ok, _rej
        sig = bytes(sig)
        if len(sig) != 64:
            return _rej("bad sig length")
        want = _h(b"rsig", bytes(pk), bytes(msg), sig[:16], out=48)
        return _ok(None) if sig[16:] == want else _rej("mismatch")


class MessageBindingRandomnessTests(unittest.TestCase):
    def test_deterministic_signing_reported_as_observed(self):
        claim = run("sig-message-binding", ToySig())
        self.assertIs(claim.verdict, Verdict.NO_DEFECT_FOUND, claim.evidence)
        self.assertIn("observed deterministic", claim.notes)
        self.assertNotIn("controlled (pinned)", claim.notes)

    def test_randomized_signing_not_called_controlled(self):
        # PINNED_RANDOMNESS in caps must not be read as signing
        # control: keygen determinism is not signing determinism.
        target = _RandomizedSig()
        from pqcheck.target import Capability
        self.assertIn(Capability.PINNED_RANDOMNESS, target.caps)
        claim = run("sig-message-binding", target)
        self.assertIs(claim.verdict, Verdict.NO_DEFECT_FOUND, claim.evidence)
        self.assertIn("not controlled by pqcheck", claim.notes)
        self.assertIn("different signatures", claim.notes)
        self.assertNotIn("controlled (pinned)", claim.notes)


class ValidationContractTests(unittest.TestCase):
    def test_default_unspecified(self):
        manifest = noble_manifest()
        self.assertEqual(manifest.validation["ek"], "unspecified")
        self.assertEqual(manifest.validation["dk"], "unspecified")

    def test_declared_values_parsed(self):
        manifest = noble_manifest({"standard": "FIPS 203", "ek": "validate-on-entry",
                                   "dk": "prevalidated-input", "basis": "docs"})
        self.assertEqual(manifest.validation["ek"], "validate-on-entry")
        self.assertEqual(manifest.validation["dk"], "prevalidated-input")
        self.assertEqual(manifest.validation["standard"], "FIPS 203")

    def test_invalid_metadata_is_manifest_error(self):
        for bad in ({"ek": "sometimes"}, {"dk": "yes"}, {"ek": 1},
                    {"unknown": "x"}, "validate-on-entry", {"basis": "  "}):
            with self.assertRaises(ManifestError, msg=repr(bad)):
                noble_manifest(bad)

    def test_nonstring_metadata_is_manifest_error_not_typeerror(self):
        # JSON arrays/objects are unhashable: a bare membership test
        # would raise TypeError instead of the clean ManifestError.
        for bad in ({"ek": ["validate-on-entry"]}, {"dk": {"mode": "x"}},
                    {"ek": ["validate-on-entry"], "dk": "validate-on-entry"}):
            with self.assertRaises(ManifestError, msg=repr(bad)):
                noble_manifest(bad)


class StrictKemRelationTests(unittest.TestCase):
    def test_clean_validate_on_entry_no_defect(self):
        for rid in ("kem-ek-rejects-noncanonical", "kem-dk-rejects-hash-mismatch"):
            claim = run(rid, PackedEkKem())
            self.assertIs(claim.verdict, Verdict.NO_DEFECT_FOUND, (rid, claim.evidence))

    def test_ek_modulus_mutant_detected(self):
        claim = run("kem-ek-rejects-noncanonical", PackedEkKem(mutant="no_ek_modulus_check"))
        self.assertIs(claim.verdict, Verdict.DEFECT_FOUND, claim.evidence)
        self.assertIn("declared validate-on-entry contract", claim.evidence)
        self.assertIn("not independently proven", claim.notes)

    def test_dk_hash_mutant_detected(self):
        claim = run("kem-dk-rejects-hash-mismatch", PackedEkKem(mutant="no_dk_hash_check"))
        self.assertIs(claim.verdict, Verdict.DEFECT_FOUND, claim.evidence)

    def test_declines_without_validate_on_entry(self):
        for contract in ("prevalidated-input", "unspecified"):
            for rid, key in (("kem-ek-rejects-noncanonical", "ek"),
                             ("kem-dk-rejects-hash-mismatch", "dk")):
                target = PackedEkKem(mutant="no_ek_modulus_check")
                target.api_contract = {**target.api_contract, key: contract}
                claim = run(rid, target)
                self.assertIs(claim.verdict, Verdict.NOT_ANSWERABLE, (contract, rid, claim.evidence))
                self.assertIn("validate-on-entry", claim.notes)

    def test_existing_relations_unchanged_meaning(self):
        # key-equivalence / honest-secret questions still fire on the
        # same mutants regardless of the strict relations existing
        claim = run("kem-ek-modulus-canonical", PackedEkKem(mutant="no_ek_modulus_check"))
        self.assertIs(claim.verdict, Verdict.DEFECT_FOUND, claim.evidence)
        claim = run("kem-dk-hash-consistency", PackedEkKem(mutant="no_dk_hash_check"))
        self.assertIs(claim.verdict, Verdict.DEFECT_FOUND, claim.evidence)

    def test_no_secret_material_in_evidence(self):
        claim = run("kem-dk-rejects-hash-mismatch", PackedEkKem(mutant="no_dk_hash_check"))
        text = claim.evidence + claim.reproduce + " ".join(claim.premises)
        self.assertNotIn("shared secret:", text.lower().replace("shared-secret", "shared secret"))


if __name__ == "__main__":
    unittest.main()
