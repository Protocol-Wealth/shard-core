"""Focused Stage 3 tests for verification, manifests, and self-testing."""

import base64
import contextlib
import io
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

from shard_core import cli, core, manifest


class TestCompleteSetVerification(unittest.TestCase):
    def test_every_two_of_three_combination_passes(self):
        shares = core.protect(b"synthetic verification material", 2, 3)
        report = core.verify_complete_set(shares)

        self.assertTrue(report.ok)
        self.assertEqual(report.supplied_indices, (1, 2, 3))
        self.assertEqual(
            report.successful_combinations,
            ((1, 2), (1, 3), (2, 3)),
        )
        self.assertEqual(report.failed_combinations, ())

    def test_corrupt_share_is_reported_by_failed_combinations(self):
        shares = core.protect(b"synthetic damaged material", 2, 3)
        raw = bytearray(base64.b64decode(shares[2]))
        raw[36] ^= 0x01
        shares[2] = base64.b64encode(bytes(raw)).decode("ascii")

        report = core.verify_complete_set(shares)

        self.assertFalse(report.ok)
        self.assertEqual(report.successful_combinations, ((1, 2),))
        self.assertEqual(report.failed_combinations, ((1, 3), (2, 3)))

    def test_combination_limit_is_checked_before_work(self):
        shares = core.protect(b"synthetic bounded verification", 2, 4)
        with mock.patch.object(
            core,
            "_combine_key",
            side_effect=AssertionError("cryptographic work started"),
        ):
            with self.assertRaises(core.RecoveryCombinationLimitError):
                core.verify_complete_set(shares, max_combinations=5)

    def test_verify_set_complete_output(self):
        shares = core.protect(b"synthetic command verification", 2, 3)
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for index, body in enumerate(shares, start=1):
                path = Path(directory) / f"share-{index}.txt"
                path.write_text(f"# synthetic\n{body}\n")
                paths.append(str(path))

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                cli._cmd_verify_set(
                    Namespace(shards=paths, require_complete=True)
                )

        rendered = output.getvalue()
        self.assertIn("format: SHRD-v2", rendered)
        self.assertIn("tested_combinations: 3", rendered)
        self.assertIn("successful_combinations: 1+2,1+3,2+3", rendered)
        self.assertIn("failed_combinations: none", rendered)
        self.assertIn("complete_set: yes", rendered)
        self.assertIn("result: PASS", rendered)

    def test_require_complete_rejects_missing_declared_share(self):
        shares = core.protect(b"synthetic incomplete inventory", 2, 3)
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for index, body in enumerate(shares[:2], start=1):
                path = Path(directory) / f"share-{index}.txt"
                path.write_text(body)
                paths.append(str(path))

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                with self.assertRaises(SystemExit):
                    cli._cmd_verify_set(
                        Namespace(shards=paths, require_complete=True)
                    )

        self.assertIn("complete_set: no", output.getvalue())
        self.assertIn("result: FAIL", output.getvalue())


class TestManifestAndSplitSelfTest(unittest.TestCase):
    def test_fordefi_split_writes_verified_manifest_without_plaintext_hash(self):
        secret = b"synthetic twelve word recovery phrase material only"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "shares"
            manifest_path = output / "manifest.json"
            with contextlib.redirect_stdout(io.StringIO()):
                cli._do_protect(
                    secret,
                    2,
                    3,
                    str(output),
                    ["protocol", "coincover", "qapture"],
                    "fordefi",
                    manifest_path=str(manifest_path),
                )

            document = json.loads(manifest_path.read_text())
            share_files = sorted(output.glob("share-*.txt"))

        self.assertEqual(document["schema"], "shard-core-manifest-v1")
        self.assertEqual(document["artifact_type"], "SHRD")
        self.assertEqual(document["format_version"], 2)
        self.assertEqual(document["threshold"], 2)
        self.assertEqual(document["declared_total"], 3)
        self.assertEqual(len(document["shares"]), 3)
        self.assertEqual(len(share_files), 3)
        self.assertTrue(
            all(not entry["label_authenticated"] for entry in document["shares"])
        )
        serialized = json.dumps(document).lower()
        self.assertNotIn("plaintext", serialized)
        self.assertNotIn("phrase_sha", serialized)
        self.assertNotIn("secret_sha", serialized)
        self.assertNotIn("word_count", serialized)
        self.assertNotIn("ciphertext_bytes", serialized)

    def test_shrd_comment_reports_payload_version(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "shares"
            with contextlib.redirect_stdout(io.StringIO()):
                cli._do_protect(
                    b"synthetic comment material",
                    2,
                    2,
                    str(output),
                    ["one", "two"],
                    "fordefi",
                )
            first_line = (output / "share-one.txt").read_text().splitlines()[0]

        self.assertEqual(
            first_line,
            "# shard-core SHRD-v2 fordefi 2-of-2 share 1/2 [one]",
        )

    def test_slip39_comment_does_not_claim_shrd(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "share-one.txt"
            cli._write_mnemonic_share(
                path,
                "one",
                "synthetic mnemonic share",
                "fordefi",
                2,
                3,
                1,
                "bip39",
                force=False,
            )
            first_line = path.read_text().splitlines()[0]

        self.assertTrue(first_line.startswith("# shard-core SLIP-39 "))
        self.assertNotIn("SHRD", first_line)

    def test_failed_internal_verification_writes_nothing(self):
        failed = core.VerificationMetadata(
            set_id="synthetic",
            threshold=2,
            declared_total=2,
            supplied_indices=(1, 2),
            successful_combinations=(),
            failed_combinations=((1, 2),),
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "shares"
            with mock.patch.object(
                core,
                "verify_complete_set",
                return_value=failed,
            ):
                with self.assertRaisesRegex(RuntimeError, "self-test failed"):
                    cli._do_protect(
                        b"synthetic self-test material",
                        2,
                        2,
                        str(output),
                        ["one", "two"],
                        "protect",
                    )

            self.assertFalse(output.exists())

    def test_manifest_builder_rejects_mixed_sets(self):
        first = core.protect(b"first synthetic manifest", 2, 2)
        second = core.protect(b"second synthetic manifest", 2, 2)
        with self.assertRaisesRegex(ValueError, "different protect sets"):
            manifest.build_shrd_manifest(
                [first[0], second[1]],
                labels=["one", "two"],
                filenames=["one.txt", "two.txt"],
                file_contents=[b"one", b"two"],
            )


if __name__ == "__main__":
    unittest.main()
