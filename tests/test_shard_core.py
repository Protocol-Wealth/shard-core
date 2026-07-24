"""Runs with stdlib unittest (no pytest needed): python -m unittest discover -s tests"""

import base64
import os
import struct
import subprocess
import sys
import unittest
from pathlib import Path

from shard_core import core, slip39

# Fast scrypt cost for tests only. Production default is 2**17.
FAST_N = 12

# Byte offsets inside a decoded protect shard (see core.HEADER_LEN).
OFF_VERSION, OFF_THRESHOLD, OFF_SHARES, OFF_INDEX = 4, 5, 6, 7
OFF_CT_LEN = 68


def _mutate(shard_b64: str, offset: int, value: int) -> str:
    """Return ``shard_b64`` with one header byte overwritten."""
    raw = bytearray(base64.b64decode(shard_b64))
    raw[offset] = value
    return base64.b64encode(bytes(raw)).decode()


def _with_ct_len(shard_b64: str, ct_len: int) -> str:
    """Return ``shard_b64`` with the declared ciphertext length overwritten."""
    raw = bytearray(base64.b64decode(shard_b64))
    raw[OFF_CT_LEN : OFF_CT_LEN + 4] = struct.pack(">I", ct_len)
    return base64.b64encode(bytes(raw)).decode()


def _protect_v1(secret: bytes, threshold: int, shares: int) -> list[str]:
    """Build v1 shards: identical layout, version byte 1, and no AAD.

    Replicates the pre-v2 writer so backward compatibility is tested against
    real v1 bytes rather than against v2 code paths.
    """
    key = core.get_random_bytes(32)
    nonce, tag, ct = core._aead_encrypt(key, secret)  # no AAD: that is the v1 format
    out = []
    for idx, sa, sb in core._split_key(threshold, shares, key):
        header = (
            core.MAGIC_PROTECT
            + bytes([1, threshold, shares, idx])
            + nonce + tag + sa + sb
            + struct.pack(">I", len(ct))
        )
        out.append(base64.b64encode(header + ct).decode("ascii"))
    return out


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

    def test_version_downgrade_fails_mac(self):
        # v2 binds the header as AAD; rewriting the version byte to 1 would
        # otherwise silently select the unauthenticated legacy path.
        blob = core.encrypt(b"downgrade me", b"pw", n_log2=FAST_N)
        raw = bytearray(base64.b64decode(blob))
        raw[OFF_VERSION] = 1
        with self.assertRaises(ValueError):
            core.decrypt(base64.b64encode(bytes(raw)).decode(), b"pw")


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


class TestMalformedShards(unittest.TestCase):
    """Every malformed shard must surface as a plain ValueError.

    Never ``binascii.Error`` (a ValueError *subclass*), ``struct.error`` or
    ``IndexError`` — the CLI catches only ValueError, so anything else becomes
    a traceback in front of a user holding key material.
    """

    def setUp(self):
        self.good = core.protect(b"a secret worth guarding", threshold=2, shares=3)[0]

    def _reject(self, shard, needle=None):
        for call in (core.parse_shard, lambda s: core.recover([s])):
            with self.assertRaises(ValueError) as cm:
                call(shard)
            # exact type: binascii.Error would also satisfy assertRaises(ValueError)
            self.assertIs(type(cm.exception), ValueError)
            if needle is not None:
                self.assertIn(needle, str(cm.exception))

    def test_empty_string(self):
        self._reject("", "truncated")

    def test_not_base64(self):
        self._reject("this is not base64!!", "not valid base64")

    def test_ten_bytes(self):
        self._reject(base64.b64encode(b"0123456789").decode(), "expected at least 72 bytes, got 10")

    def test_wrong_magic(self):
        self._reject(_mutate(self.good, 0, ord("X")), "not a shard-core protect shard")

    def test_unsupported_version(self):
        self._reject(_mutate(self.good, OFF_VERSION, 7), "unsupported shard-core format version 7")

    def test_ct_len_larger_than_actual(self):
        raw = base64.b64decode(self.good)
        actual = len(raw) - core.HEADER_LEN
        self._reject(
            _with_ct_len(self.good, actual + 100),
            f"header claims {actual + 100} ciphertext bytes, {actual} present",
        )

    def test_trailing_bytes(self):
        padded = base64.b64encode(base64.b64decode(self.good) + b"junk").decode()
        self._reject(padded, "trailing garbage")

    def test_threshold_one(self):
        self._reject(_mutate(self.good, OFF_THRESHOLD, 1), "threshold=1")

    def test_threshold_above_shares(self):
        self._reject(_mutate(self.good, OFF_THRESHOLD, 4), "threshold=4 shares=3")

    def test_index_zero(self):
        self._reject(_mutate(self.good, OFF_INDEX, 0), "index 0 is out of range")

    def test_index_above_shares(self):
        self._reject(_mutate(self.good, OFF_INDEX, 9), "index 9 is out of range")


class TestMalformedEncryptBlobs(unittest.TestCase):
    def _reject(self, blob, needle):
        with self.assertRaises(ValueError) as cm:
            core.decrypt(blob, b"pw")
        self.assertIs(type(cm.exception), ValueError)
        self.assertIn(needle, str(cm.exception))

    def test_empty_string(self):
        self._reject("", "truncated")

    def test_not_base64(self):
        self._reject("nope!!", "not valid base64")

    def test_short_blob(self):
        self._reject(base64.b64encode(b"SHEN" + b"\x02" * 8).decode(), "expected at least 53 bytes")

    def test_wrong_magic(self):
        blob = core.encrypt(b"x", b"pw", n_log2=FAST_N)
        raw = bytearray(base64.b64decode(blob))
        raw[0] = ord("X")
        self._reject(base64.b64encode(bytes(raw)).decode(), "not a shard-core encrypt blob")

    def test_unsupported_version(self):
        blob = core.encrypt(b"x", b"pw", n_log2=FAST_N)
        raw = bytearray(base64.b64decode(blob))
        raw[OFF_VERSION] = 7
        self._reject(base64.b64encode(bytes(raw)).decode(), "unsupported shard-core format version 7")


class TestNoAssertDependence(unittest.TestCase):
    """`python -O` strips asserts; the shard paths must not depend on them."""

    def test_protect_recover_suite_passes_under_O(self):
        repo = Path(__file__).resolve().parents[1]
        env = dict(os.environ, PYTHONPATH=str(repo / "src"))
        proc = subprocess.run(
            [sys.executable, "-O", "-m", "unittest",
             "tests.test_shard_core.TestProtectRecover"],
            cwd=str(repo), env=env, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")


class TestFormatV2AAD(unittest.TestCase):
    """v2 binds the shard header as AEAD associated data."""

    def test_new_shards_are_v2(self):
        meta = core.parse_shard(core.protect(b"x", threshold=2, shares=3)[0])
        self.assertEqual(meta["version"], 2)

    def test_tampered_threshold_byte_fails_mac(self):
        # Raise the threshold on EVERY shard so the set stays self-consistent
        # and enough shards are supplied: only the AAD can catch this.
        shards = core.protect(b"header integrity", threshold=2, shares=3)
        tampered = [_mutate(s, OFF_THRESHOLD, 3) for s in shards]
        self.assertEqual(core.parse_shard(tampered[0])["threshold"], 3)
        with self.assertRaises(ValueError):
            core.recover(tampered)  # 3 shards supplied for the claimed 3-of-3

    def test_tampered_shares_byte_fails_mac(self):
        shards = core.protect(b"header integrity", threshold=2, shares=3)
        tampered = [_mutate(s, OFF_SHARES, 4) for s in shards]
        self.assertEqual(core.parse_shard(tampered[0])["shares"], 4)
        with self.assertRaises(ValueError):
            core.recover(tampered[:2])  # threshold still 2, so enough shards

    def test_untampered_v2_still_recovers(self):
        secret = b"control case"
        shards = core.protect(secret, threshold=2, shares=3)
        self.assertEqual(core.recover(shards[:2]), secret)


class TestV1BackwardCompat(unittest.TestCase):
    """v1 shards predate the AAD binding and must stay readable."""

    def test_v1_shards_still_recover(self):
        secret = b"written by shard-core v1"
        shards = _protect_v1(secret, threshold=2, shares=3)
        self.assertEqual(core.parse_shard(shards[0])["version"], 1)
        for combo in [(0, 1), (0, 2), (1, 2)]:
            self.assertEqual(core.recover([shards[i] for i in combo]), secret)

    def test_v1_ciphertext_tamper_still_detected(self):
        shards = _protect_v1(b"v1 integrity", threshold=2, shares=3)
        raw = bytearray(base64.b64decode(shards[0]))
        raw[-1] ^= 0xFF
        shards[0] = base64.b64encode(bytes(raw)).decode()
        with self.assertRaises(ValueError):
            core.recover([shards[0], shards[1]])

    def test_v1_header_tamper_is_not_detected_by_design(self):
        # Documents the reason to re-shard: v1 headers are unauthenticated.
        secret = b"v1 header is unbound"
        shards = _protect_v1(secret, threshold=2, shares=3)
        relabelled = [_mutate(s, OFF_SHARES, 4) for s in shards]
        self.assertEqual(core.recover(relabelled[:2]), secret)


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
