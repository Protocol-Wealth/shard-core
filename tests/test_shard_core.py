"""Runs with stdlib unittest (no pytest needed): python -m unittest discover -s tests"""

import unittest

from shard_core import core, slip39

# Fast scrypt cost for tests only. Production default is 2**17.
FAST_N = 12


class TestEncryptDecrypt(unittest.TestCase):
    def test_roundtrip(self):
        secret = b"correct horse battery staple"
        blob = core.encrypt(secret, b"hunter2", n_log2=FAST_N)
        self.assertEqual(core.decrypt(blob, b"hunter2"), secret)

    def test_wrong_passphrase_fails(self):
        blob = core.encrypt(b"top secret", b"right", n_log2=FAST_N)
        with self.assertRaises(ValueError):
            core.decrypt(blob, b"wrong")

    def test_binary_secret(self):
        secret = bytes(range(256)) * 4
        blob = core.encrypt(secret, b"pw", n_log2=FAST_N)
        self.assertEqual(core.decrypt(blob, b"pw"), secret)


class TestProtectRecover(unittest.TestCase):
    def test_2_of_3_all_pairs(self):
        secret = b"afraid pole typical never dad symbol present stable"
        shards = core.protect(secret, threshold=2, shares=3)
        self.assertEqual(len(shards), 3)
        for combo in [(0, 1), (0, 2), (1, 2), (0, 1, 2)]:
            self.assertEqual(core.recover([shards[i] for i in combo]), secret)

    def test_below_threshold_raises(self):
        shards = core.protect(b"secret", threshold=3, shares=5)
        with self.assertRaises(ValueError):
            core.recover([shards[0], shards[1]])

    def test_3_of_5(self):
        secret = b"a slightly longer secret passphrase value here"
        shards = core.protect(secret, threshold=3, shares=5)
        self.assertEqual(core.recover([shards[4], shards[1], shards[0]]), secret)

    def test_threshold_min_2(self):
        # a single share must never reconstruct the secret
        with self.assertRaises(ValueError):
            core.protect(b"solo", threshold=1, shares=3)

    def test_tampered_shard_detected(self):
        import base64
        secret = b"integrity matters"
        shards = core.protect(secret, threshold=2, shares=3)
        raw = bytearray(base64.b64decode(shards[0]))
        raw[-1] ^= 0xFF  # flip a ciphertext byte
        shards[0] = base64.b64encode(bytes(raw)).decode()
        with self.assertRaises(ValueError):
            core.recover([shards[0], shards[1]])

    def test_parse_shard_header(self):
        shards = core.protect(b"x", threshold=2, shares=3)
        meta = core.parse_shard(shards[0])
        self.assertEqual(meta["threshold"], 2)
        self.assertEqual(meta["shares"], 3)
        self.assertIn(meta["index"], (1, 2, 3))

    def test_bad_params(self):
        with self.assertRaises(ValueError):
            core.protect(b"x", threshold=4, shares=3)


class TestNormalizeLabels(unittest.TestCase):
    def test_cases(self):
        nl = core.normalize_labels
        self.assertEqual(nl([], 3), ["01", "02", "03"])
        self.assertEqual(nl(["shard"], 2), ["shard-1", "shard-2"])  # the reported case
        self.assertEqual(nl(["a", "b"], 2), ["a", "b"])
        self.assertEqual(nl(["a"], 1), ["a"])
        self.assertEqual(nl(["a", "b"], 4), ["a", "b", "03", "04"])
        self.assertEqual(nl(["a", "b", "c"], 2), ["a", "b"])
        self.assertEqual(nl([" x ", "", "y"], 3), ["x", "y", "03"])


@unittest.skipUnless(slip39.available(), "slip39 extra not installed")
class TestSlip39(unittest.TestCase):
    def test_master_secret_2_of_3(self):
        secret = bytes(range(32))
        shares = slip39.split_master_secret(secret, threshold=2, shares=3)
        self.assertEqual(len(shares), 3)
        for combo in [(0, 1), (0, 2), (1, 2)]:
            self.assertEqual(slip39.combine([shares[i] for i in combo]), secret)

    def test_bip39_roundtrip(self):
        from mnemonic import Mnemonic

        phrase = Mnemonic("english").generate(strength=128)  # valid 12-word BIP-39
        shares = slip39.split_bip39(phrase, threshold=2, shares=3)
        entropy = slip39.combine([shares[1], shares[2]])
        self.assertEqual(slip39.entropy_to_bip39(entropy), phrase)

    def test_passphrase_required(self):
        secret = bytes(range(16))
        shares = slip39.split_master_secret(secret, 2, 3, passphrase=b"TREZOR")
        # right passphrase recovers; empty passphrase yields a different (wrong) secret
        self.assertEqual(slip39.combine([shares[0], shares[1]], passphrase=b"TREZOR"), secret)
        self.assertNotEqual(slip39.combine([shares[0], shares[1]], passphrase=b""), secret)

    def test_bad_length_rejected(self):
        with self.assertRaises(ValueError):
            slip39.split_master_secret(b"12345", 2, 3)  # 5 bytes, invalid


if __name__ == "__main__":
    unittest.main()
