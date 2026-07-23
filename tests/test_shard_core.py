"""Runs with stdlib unittest (no pytest needed): python -m unittest discover -s tests"""

import unittest

from shard_core import core

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

    def test_1_of_1(self):
        shards = core.protect(b"solo", threshold=1, shares=1)
        self.assertEqual(core.recover(shards), b"solo")

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


if __name__ == "__main__":
    unittest.main()
