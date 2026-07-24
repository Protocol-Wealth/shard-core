"""Focused Stage 2 tests for resilient, unambiguous shard recovery."""

import base64
import unittest
from unittest import mock

from shard_core import core


class TestRecoveryResilience(unittest.TestCase):
    def test_extra_corrupt_key_share_is_bypassed(self):
        secret = b"synthetic twelve word phrase for testing only"
        shares = core.protect(secret, threshold=2, shares=3)
        raw = bytearray(base64.b64decode(shares[2]))
        raw[36] ^= 0x01
        damaged = base64.b64encode(bytes(raw)).decode("ascii")

        recovered, report = core.recover_with_report([
            shares[0],
            shares[1],
            damaged,
        ])

        self.assertEqual(recovered, secret)
        self.assertIn((1, 2), report.authenticating_combinations)
        self.assertIn((1, 3), report.failed_combinations)
        self.assertIn((2, 3), report.failed_combinations)
        self.assertIn(3, report.suspect_indices)

    def test_extra_corrupt_ciphertext_copy_does_not_poison_set(self):
        secret = b"synthetic recovery phrase"
        shares = core.protect(secret, 2, 3)
        raw = bytearray(base64.b64decode(shares[2]))
        raw[-1] ^= 0x01
        damaged = base64.b64encode(bytes(raw)).decode("ascii")

        recovered, report = core.recover_with_report([
            shares[0],
            shares[1],
            damaged,
        ])

        self.assertEqual(recovered, secret)
        self.assertEqual(report.authenticating_combinations, ((1, 2),))
        self.assertIn(3, report.suspect_indices)
        self.assertEqual(len(report.rejected_set_ids), 1)

    def test_conflicting_duplicate_index_is_rejected(self):
        shares = core.protect(b"synthetic secret", 2, 3)
        raw = bytearray(base64.b64decode(shares[0]))
        raw[36] ^= 0x01
        conflicting_index_one = base64.b64encode(bytes(raw)).decode("ascii")

        with self.assertRaisesRegex(
            ValueError,
            "conflicting payloads for share index 1",
        ):
            core.recover_with_report([
                shares[0],
                conflicting_index_one,
                shares[1],
            ])

    def test_identical_duplicates_are_tolerated_and_reported(self):
        secret = b"synthetic duplicate test"
        shares = core.protect(secret, 2, 3)

        recovered, report = core.recover_with_report([
            shares[0],
            shares[0],
            shares[1],
        ])

        self.assertEqual(recovered, secret)
        self.assertEqual(report.duplicate_indices, (1,))
        self.assertEqual(report.authenticating_combinations, ((1, 2),))

    def test_unrelated_extra_share_is_ignored_and_reported(self):
        secret = b"selected synthetic set"
        selected = core.protect(secret, 2, 3)
        unrelated = core.protect(b"unrelated synthetic set", 2, 3)

        recovered, report = core.recover_with_report([
            selected[0],
            selected[1],
            unrelated[2],
        ])

        self.assertEqual(recovered, secret)
        self.assertEqual(report.authenticating_combinations, ((1, 2),))
        self.assertIn(3, report.suspect_indices)
        self.assertEqual(len(report.rejected_set_ids), 1)

    def test_two_complete_valid_sets_are_ambiguous(self):
        first = core.protect(b"first synthetic set", 2, 3)
        second = core.protect(b"second synthetic set", 2, 3)

        with self.assertRaises(core.RecoveryAmbiguityError):
            core.recover_with_report([
                first[0],
                first[1],
                second[0],
                second[1],
            ])

    def test_aggregate_combination_limit_is_enforced_before_work(self):
        first = core.protect(b"first synthetic set", 2, 3)
        second = core.protect(b"second synthetic set", 2, 3)

        with mock.patch.object(
            core,
            "_combine_key",
            side_effect=AssertionError("cryptographic work started"),
        ):
            with self.assertRaisesRegex(
                core.RecoveryCombinationLimitError,
                "require 6 combinations; limit is 5",
            ):
                core.recover_with_report(
                    first + second,
                    max_combinations=5,
                )

    def test_every_two_of_three_pair_authenticates(self):
        secret = b"synthetic all-pairs test"
        shares = core.protect(secret, 2, 3)

        recovered, report = core.recover_with_report(shares)

        self.assertEqual(recovered, secret)
        self.assertEqual(
            report.authenticating_combinations,
            ((1, 2), (1, 3), (2, 3)),
        )
        self.assertEqual(report.failed_combinations, ())
        self.assertEqual(report.suspect_indices, ())

    def test_set_identifier_is_stable_and_run_specific(self):
        first = core.protect(b"synthetic set id", 2, 3)
        second = core.protect(b"synthetic set id", 2, 3)

        first_ids = {
            core.protect_set_id(core.parse_shard(shard))
            for shard in first
        }
        second_id = core.protect_set_id(core.parse_shard(second[0]))

        self.assertEqual(len(first_ids), 1)
        self.assertNotIn(second_id, first_ids)

    def test_legacy_recover_api_returns_plaintext_only(self):
        secret = b"synthetic compatibility wrapper"
        shares = core.protect(secret, 2, 3)
        self.assertEqual(core.recover(shares[:2]), secret)


if __name__ == "__main__":
    unittest.main()
