"""Focused Stage 1 tests for secret-safe local file behavior."""

import contextlib
import io
import os
import stat
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

from shard_core import safeio
from shard_core import cli


class TestSafeWrites(unittest.TestCase):
    def test_new_file_is_mode_0600_and_directory_is_mode_0700(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "private"
            target = parent / "secret.txt"

            safeio.atomic_write_bytes(target, b"synthetic secret")

            self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(target.read_bytes(), b"synthetic secret")

    def test_existing_file_requires_force(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "secret.txt"
            target.write_bytes(b"old")

            with self.assertRaises(FileExistsError):
                safeio.atomic_write_bytes(target, b"new")

            self.assertEqual(target.read_bytes(), b"old")
            safeio.atomic_write_bytes(target, b"new", force=True)
            self.assertEqual(target.read_bytes(), b"new")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_force_does_not_replace_through_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            protected = root / "protected.txt"
            link = root / "output.txt"
            protected.write_text("do not replace")
            link.symlink_to(protected)

            with self.assertRaises(safeio.UnsafeOutputPath):
                safeio.atomic_write_bytes(link, b"new secret", force=True)

            self.assertEqual(protected.read_text(), "do not replace")

    def test_preflight_rejects_duplicate_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "same.txt"
            with self.assertRaisesRegex(ValueError, "duplicate output"):
                safeio.preflight_output_paths([target, target])

    def test_failed_split_preflight_writes_no_partial_share(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "shares"
            output.mkdir()
            existing = output / "share-02.txt"
            existing.write_text("existing")

            with self.assertRaises(FileExistsError):
                cli._do_protect(
                    b"synthetic secret",
                    2,
                    2,
                    str(output),
                    ["01", "02"],
                    "protect",
                )

            self.assertFalse((output / "share-01.txt").exists())
            self.assertEqual(existing.read_text(), "existing")

    def test_limited_read_rejects_oversized_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "input.txt"
            target.write_bytes(b"12345")
            with self.assertRaisesRegex(ValueError, "too large"):
                safeio.read_limited_bytes(target, max_bytes=4)


class TestSecretOutputParser(unittest.TestCase):
    def setUp(self):
        self.parser = cli.build_parser()

    def _reject(self, argv):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                self.parser.parse_args(argv)

    def test_sensitive_commands_require_explicit_output(self):
        self._reject(["decrypt"])
        self._reject(["recover", "share-1.txt", "share-2.txt"])
        self._reject(["fordefi", "combine", "share-1.txt", "share-2.txt"])
        self._reject(["slip39", "combine", "share-1.txt", "share-2.txt"])

    def test_output_and_stdout_are_mutually_exclusive(self):
        self._reject([
            "fordefi",
            "combine",
            "--output",
            "phrase.txt",
            "--stdout",
            "share-1.txt",
            "share-2.txt",
        ])

    def test_output_dash_requires_explicit_stdout(self):
        args = Namespace(stdout=False, output="-", force=False)
        with self.assertRaisesRegex(ValueError, "use --stdout"):
            cli._emit_secret(args, b"synthetic secret")


class TestForcePropagation(unittest.TestCase):
    def test_fordefi_slip39_split_forwards_force(self):
        args = Namespace(
            phrase_file="synthetic-phrase.txt",
            allow_nonstandard_phrase=False,
            allow_insecure_phrase_file=False,
            labels=None,
            shares=3,
            threshold=2,
            slip39=True,
            out_dir="synthetic-output",
            force=True,
            manifest=None,
        )
        with mock.patch.object(
            cli.fordefi_support,
            "read_recovery_phrase_file",
            return_value=(
                b"alpha bravo charlie delta echo foxtrot "
                b"golf hotel india juliet kilo lima"
            ),
        ), mock.patch.object(
            cli.slip39,
            "split_bip39",
            return_value=["share one", "share two", "share three"],
        ), mock.patch.object(
            cli,
            "_do_slip39_split",
        ) as split:
            with contextlib.redirect_stdout(io.StringIO()):
                cli._cmd_fordefi_split(args)

        self.assertTrue(split.call_args.kwargs["force"])


class TestPassphraseSources(unittest.TestCase):
    @staticmethod
    def _args(**overrides):
        values = {
            "passphrase_env": None,
            "passphrase_file": None,
            "allow_insecure_passphrase_file": False,
        }
        values.update(overrides)
        return Namespace(**values)

    def test_empty_prompt_passphrase_is_rejected(self):
        with mock.patch("getpass.getpass", return_value=""):
            with self.assertRaisesRegex(ValueError, "empty passphrase"):
                cli._get_passphrase(self._args(), confirm=False)

    def test_empty_environment_passphrase_is_rejected_and_warned(self):
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, {"SHARD_CORE_TEST_PW": ""}):
            with contextlib.redirect_stderr(stderr):
                with self.assertRaisesRegex(ValueError, "empty passphrase"):
                    cli._get_passphrase(
                        self._args(passphrase_env="SHARD_CORE_TEST_PW"),
                        confirm=False,
                    )
        self.assertIn("environment-variable passphrases", stderr.getvalue())

    def test_empty_file_passphrase_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "passphrase"
            target.write_bytes(b"\n")
            target.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "empty passphrase"):
                cli._get_passphrase(
                    self._args(passphrase_file=str(target)),
                    confirm=False,
                )

    @unittest.skipUnless(os.name == "posix", "POSIX permissions required")
    def test_insecure_passphrase_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "passphrase"
            target.write_bytes(b"synthetic passphrase")
            target.chmod(0o644)

            with self.assertRaisesRegex(ValueError, "group/world accessible"):
                cli._get_passphrase(
                    self._args(passphrase_file=str(target)),
                    confirm=False,
                )

            self.assertEqual(
                cli._get_passphrase(
                    self._args(
                        passphrase_file=str(target),
                        allow_insecure_passphrase_file=True,
                    ),
                    confirm=False,
                ),
                b"synthetic passphrase",
            )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_passphrase_file_symlink_is_rejected_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "passphrase"
            link = root / "passphrase-link"
            target.write_bytes(b"synthetic passphrase")
            target.chmod(0o600)
            link.symlink_to(target)

            with self.assertRaisesRegex(ValueError, "symlink passphrase"):
                cli._get_passphrase(
                    self._args(passphrase_file=str(link)),
                    confirm=False,
                )

            self.assertEqual(
                cli._get_passphrase(
                    self._args(
                        passphrase_file=str(link),
                        allow_insecure_passphrase_file=True,
                    ),
                    confirm=False,
                ),
                b"synthetic passphrase",
            )


if __name__ == "__main__":
    unittest.main()
