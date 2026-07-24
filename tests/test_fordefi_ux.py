"""Focused Stage 4 tests for Fordefi input UX and credential generation."""

import contextlib
import io
import os
import stat
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

from shard_core import cli, fordefi, wizard

PHRASE = (
    "alpha bravo charlie delta echo foxtrot "
    "golf hotel india juliet kilo lima"
)


class TestFordefiCanonicalization(unittest.TestCase):
    def test_twelve_lowercase_words_are_accepted(self):
        self.assertEqual(
            fordefi.canonicalize_recovery_phrase(PHRASE),
            PHRASE.encode("ascii"),
        )

    def test_extra_whitespace_is_canonicalized(self):
        spaced = (
            " \talpha  bravo\ncharlie delta echo foxtrot "
            "golf hotel india juliet kilo lima\r\n"
        )
        self.assertEqual(
            fordefi.canonicalize_recovery_phrase(spaced),
            PHRASE.encode("ascii"),
        )

    def test_eleven_and_thirteen_words_are_rejected(self):
        words = PHRASE.split()
        with self.assertRaisesRegex(ValueError, "12 words; got 11"):
            fordefi.canonicalize_recovery_phrase(" ".join(words[:11]))
        with self.assertRaisesRegex(ValueError, "12 words; got 13"):
            fordefi.canonicalize_recovery_phrase(
                " ".join(words + ["mike"])
            )

    def test_uppercase_and_punctuation_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "lowercase ASCII"):
            fordefi.canonicalize_recovery_phrase(
                PHRASE.replace("alpha", "Alpha")
            )
        with self.assertRaisesRegex(ValueError, "lowercase ASCII"):
            fordefi.canonicalize_recovery_phrase(
                PHRASE.replace("alpha", "alpha!")
            )

    def test_nonstandard_override_does_not_change_spelling(self):
        self.assertEqual(
            fordefi.canonicalize_recovery_phrase(
                "  Mixed CASE phrase!  ",
                allow_nonstandard=True,
            ),
            b"Mixed CASE phrase!",
        )

    def test_non_ascii_nul_and_control_characters_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "ASCII"):
            fordefi.canonicalize_recovery_phrase("caf\u00e9")
        with self.assertRaisesRegex(ValueError, "NUL"):
            fordefi.canonicalize_recovery_phrase(b"alpha\x00bravo")
        with self.assertRaisesRegex(ValueError, "control"):
            fordefi.canonicalize_recovery_phrase(b"alpha\x01bravo")


class TestFordefiInput(unittest.TestCase):
    def test_hidden_double_entry_canonicalizes_and_matches(self):
        args = Namespace(allow_nonstandard_phrase=False)
        with mock.patch.object(
            sys.stdin,
            "isatty",
            return_value=True,
        ), mock.patch(
            "getpass.getpass",
            side_effect=[PHRASE, f"  {PHRASE}  "],
        ):
            self.assertEqual(
                cli._prompt_fordefi_phrase(args),
                PHRASE.encode("ascii"),
            )

    def test_hidden_double_entry_mismatch_is_rejected(self):
        changed = PHRASE.replace("lima", "mike")
        with mock.patch.object(
            sys.stdin,
            "isatty",
            return_value=True,
        ), mock.patch(
            "getpass.getpass",
            side_effect=[PHRASE, changed],
        ):
            with self.assertRaisesRegex(ValueError, "do not match"):
                cli._prompt_fordefi_phrase(
                    Namespace(allow_nonstandard_phrase=False)
                )

    def test_interactive_entry_requires_tty(self):
        with mock.patch.object(sys.stdin, "isatty", return_value=False):
            with self.assertRaisesRegex(ValueError, "requires a TTY"):
                cli._prompt_fordefi_phrase(
                    Namespace(allow_nonstandard_phrase=False)
                )

    @unittest.skipUnless(os.name == "posix", "POSIX permissions required")
    def test_phrase_file_requires_private_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "phrase"
            path.write_text(PHRASE)
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "group/world accessible"):
                fordefi.read_recovery_phrase_file(path)

            self.assertEqual(
                fordefi.read_recovery_phrase_file(
                    path,
                    allow_insecure=True,
                ),
                PHRASE.encode("ascii"),
            )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_phrase_file_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            phrase = root / "phrase"
            link = root / "phrase-link"
            phrase.write_text(PHRASE)
            phrase.chmod(0o600)
            link.symlink_to(phrase)
            with self.assertRaisesRegex(ValueError, "symlink Fordefi"):
                fordefi.read_recovery_phrase_file(link)

    def test_fordefi_command_passes_canonical_phrase_to_shrd(self):
        args = Namespace(
            phrase_file=None,
            allow_nonstandard_phrase=False,
            allow_insecure_phrase_file=False,
            labels="protocol,coincover,qapture",
            shares=3,
            threshold=2,
            slip39=False,
            out_dir="synthetic-output",
            force=False,
            manifest=None,
        )
        with mock.patch.object(
            cli,
            "_prompt_fordefi_phrase",
            return_value=PHRASE.encode("ascii"),
        ), mock.patch.object(cli, "_do_protect") as protect:
            with contextlib.redirect_stdout(io.StringIO()):
                cli._cmd_fordefi_split(args)

        self.assertEqual(protect.call_args.args[0], PHRASE.encode("ascii"))
        self.assertEqual(protect.call_args.args[5], "fordefi")


class TestGenerateKeyAndWizard(unittest.TestCase):
    def test_generate_key_writes_private_hex_without_displaying_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wrap.key"
            output = io.StringIO()
            with mock.patch(
                "secrets.token_bytes",
                return_value=bytes(range(32)),
            ), contextlib.redirect_stdout(output):
                cli._cmd_generate_key(
                    Namespace(
                        bytes=32,
                        encoding="hex",
                        output=str(path),
                        force=False,
                    )
                )

            expected = bytes(range(32)).hex()
            self.assertEqual(path.read_text(), expected + "\n")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertNotIn(expected, output.getvalue())

    def test_generate_key_rejects_stdout_and_short_key(self):
        with self.assertRaisesRegex(ValueError, "refuses stdout"):
            cli._cmd_generate_key(
                Namespace(
                    bytes=32,
                    encoding="hex",
                    output="-",
                    force=False,
                )
            )
        with self.assertRaisesRegex(ValueError, "between 16 and 1024"):
            cli._cmd_generate_key(
                Namespace(
                    bytes=8,
                    encoding="hex",
                    output="unused",
                    force=False,
                )
            )

    def test_fordefi_wizard_never_attempts_slip39(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "shares"
            with mock.patch.object(
                sys.stdin,
                "isatty",
                return_value=True,
            ), mock.patch(
                "getpass.getpass",
                side_effect=[PHRASE, PHRASE],
            ), mock.patch.object(
                wizard,
                "_ask_int",
                return_value=2,
            ), mock.patch.object(
                wizard,
                "_ask",
                side_effect=["", str(output)],
            ), mock.patch.object(
                wizard.slip39,
                "split_bip39",
                side_effect=AssertionError("SLIP-39 was selected"),
            ), contextlib.redirect_stdout(io.StringIO()):
                wizard._wizard_split(fordefi_mode=True)

            shares = sorted(output.glob("share-*.txt"))

        self.assertEqual(len(shares), 2)


if __name__ == "__main__":
    unittest.main()
