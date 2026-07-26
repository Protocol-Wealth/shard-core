"""Synthetic tests for the vendor-neutral custody decision flow."""

import contextlib
import io
import sys
import tempfile
import unittest
from itertools import combinations
from pathlib import Path
from unittest import mock

from shard_core import core, wizard

ROOT = Path(__file__).resolve().parents[1]
FORDEFI_PHRASE = (
    "alpha bravo charlie delta echo foxtrot "
    "golf hotel india juliet kilo lima"
)
BIP39_FIXTURE = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


class TestCustodyWizard(unittest.TestCase):
    def test_native_provider_route_creates_no_shard_core_artifact(self):
        output = io.StringIO()
        with mock.patch.object(
            wizard,
            "_ask",
            return_value="1",
        ), mock.patch.object(
            wizard,
            "_wizard_encrypt",
        ) as encrypt, mock.patch.object(
            wizard,
            "_wizard_split",
        ) as split, contextlib.redirect_stdout(output):
            wizard._wizard_custody()

        encrypt.assert_not_called()
        split.assert_not_called()
        rendered = output.getvalue()
        self.assertIn("No shard-core artifact will be created", rendered)
        self.assertIn("never requests provider API credentials", rendered)
        self.assertIn("performs an upload", rendered)

    def test_unconfirmed_shen_holder_stops_before_reading_secret(self):
        output = io.StringIO()
        with mock.patch.object(
            wizard,
            "_ask",
            return_value="2",
        ), mock.patch.object(
            wizard,
            "_yn",
            return_value=False,
        ), mock.patch.object(
            wizard,
            "_wizard_encrypt",
        ) as encrypt, contextlib.redirect_stdout(output):
            wizard._wizard_custody()

        encrypt.assert_not_called()
        self.assertIn(
            "obtain the holder's written format and release requirements",
            output.getvalue(),
        )

    def test_confirmed_shen_holder_routes_to_existing_encrypt_flow(self):
        with mock.patch.object(
            wizard,
            "_ask",
            return_value="2",
        ), mock.patch.object(
            wizard,
            "_yn",
            side_effect=[True, False],
        ), mock.patch.object(
            wizard,
            "_wizard_encrypt",
        ) as encrypt, contextlib.redirect_stdout(io.StringIO()):
            wizard._wizard_custody()

        encrypt.assert_called_once_with(fordefi_mode=False)

    def test_fordefi_shen_holder_uses_validated_fordefi_flow(self):
        with mock.patch.object(
            wizard,
            "_ask",
            return_value="2",
        ), mock.patch.object(
            wizard,
            "_yn",
            side_effect=[True, True],
        ), mock.patch.object(
            wizard,
            "_wizard_encrypt",
        ) as encrypt, contextlib.redirect_stdout(io.StringIO()):
            wizard._wizard_custody()

        encrypt.assert_called_once_with(fordefi_mode=True)

    def test_threshold_route_forces_shrd_instead_of_slip39(self):
        with mock.patch.object(
            wizard,
            "_ask",
            return_value="3",
        ), mock.patch.object(
            wizard,
            "_yn",
            side_effect=[True, False],
        ), mock.patch.object(
            wizard,
            "_wizard_split",
        ) as split, contextlib.redirect_stdout(io.StringIO()):
            wizard._wizard_custody()

        split.assert_called_once_with(
            fordefi_mode=False,
            allow_slip39=False,
        )

    def test_unconfirmed_threshold_holders_stop_before_reading_secret(self):
        output = io.StringIO()
        with mock.patch.object(
            wizard,
            "_ask",
            return_value="3",
        ), mock.patch.object(
            wizard,
            "_yn",
            return_value=False,
        ), mock.patch.object(
            wizard,
            "_wizard_split",
        ) as split, contextlib.redirect_stdout(output):
            wizard._wizard_custody()

        split.assert_not_called()
        self.assertIn("Stop and obtain every holder", output.getvalue())

    def test_fordefi_threshold_uses_validated_fordefi_flow(self):
        with mock.patch.object(
            wizard,
            "_ask",
            return_value="3",
        ), mock.patch.object(
            wizard,
            "_yn",
            side_effect=[True, True],
        ), mock.patch.object(
            wizard,
            "_wizard_split",
        ) as split, contextlib.redirect_stdout(io.StringIO()):
            wizard._wizard_custody()

        split.assert_called_once_with(
            fordefi_mode=True,
            allow_slip39=False,
        )

    def test_main_wizard_exposes_custody_route_first(self):
        output = io.StringIO()
        with mock.patch.object(
            wizard,
            "_ask",
            return_value="6",
        ), mock.patch.object(
            wizard,
            "_wizard_custody",
        ) as custody, contextlib.redirect_stdout(output):
            wizard.run_wizard()

        custody.assert_called_once_with()
        self.assertIn("Choose a custody route", output.getvalue())

    def test_main_wizard_keeps_fordefi_as_enter_default(self):
        with mock.patch.object(
            wizard,
            "_ask",
            return_value="1",
        ), mock.patch.object(
            wizard,
            "_wizard_split",
        ) as split, contextlib.redirect_stdout(io.StringIO()):
            wizard.run_wizard()

        split.assert_called_once_with(fordefi_mode=True)

    def test_main_wizard_preserves_existing_numeric_routes(self):
        expected = {
            "2": ("_wizard_split", {"fordefi_mode": False}),
            "3": ("_wizard_recover", {}),
            "4": ("_wizard_encrypt", {}),
            "5": ("_wizard_decrypt", {}),
            "6": ("_wizard_custody", {}),
        }
        for choice, (selected_name, kwargs) in expected.items():
            with self.subTest(choice=choice), mock.patch.object(
                wizard,
                "_ask",
                return_value=choice,
            ), mock.patch.multiple(
                wizard,
                _wizard_split=mock.DEFAULT,
                _wizard_recover=mock.DEFAULT,
                _wizard_encrypt=mock.DEFAULT,
                _wizard_decrypt=mock.DEFAULT,
                _wizard_custody=mock.DEFAULT,
            ) as routes, contextlib.redirect_stdout(io.StringIO()):
                wizard.run_wizard()

            routes[selected_name].assert_called_once_with(**kwargs)
            for route_name, route in routes.items():
                if route_name != selected_name:
                    route.assert_not_called()

    def test_provider_route_names_coincover_and_station70(self):
        output = io.StringIO()
        with mock.patch.object(
            wizard,
            "_ask",
            side_effect=["1", "invalid"],
        ), contextlib.redirect_stdout(output):
            wizard._wizard_custody()

        rendered = output.getvalue()
        self.assertIn("CoinCover", rendered)
        self.assertIn("Station70", rendered)


class TestCustodyFileSafety(unittest.TestCase):
    def test_file_based_shrd_round_trip_preserves_trailing_newlines(self):
        expected_bytes = b"synthetic report\r\n"
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "report.txt"
            out = Path(directory) / "shares"
            source.write_bytes(expected_bytes)
            with mock.patch.object(
                wizard,
                "_ask",
                side_effect=["1", str(source), "", str(out)],
            ), mock.patch.object(
                wizard,
                "_ask_int",
                return_value=2,
            ), contextlib.redirect_stdout(io.StringIO()):
                wizard._wizard_split(
                    fordefi_mode=False,
                    allow_slip39=False,
                )

            payloads = [
                wizard._payload(str(path))
                for path in sorted(out.glob("share-*.txt"))
            ]

        self.assertEqual(len(payloads), 2)
        self.assertNotIn(None, payloads)
        self.assertEqual(core.recover(payloads), expected_bytes)

    @unittest.skipUnless(wizard.slip39.available(), "slip39 extra not installed")
    def test_written_slip39_shares_verify_with_slip39(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "shares"
            output = io.StringIO()
            with mock.patch.object(
                sys.stdin,
                "isatty",
                return_value=True,
            ), mock.patch.object(
                wizard,
                "_ask",
                side_effect=["2", "", str(out)],
            ), mock.patch.object(
                wizard,
                "_ask_int",
                side_effect=[3, 2],
            ), mock.patch.object(
                wizard,
                "_yn",
                return_value=True,
            ), mock.patch(
                "getpass.getpass",
                return_value=BIP39_FIXTURE,
            ), contextlib.redirect_stdout(output):
                wizard._wizard_split(fordefi_mode=False)

            payloads = [
                wizard._payload(str(path))
                for path in sorted(out.glob("share-*.txt"))
            ]

        self.assertEqual(len(payloads), 3)
        self.assertNotIn(None, payloads)
        expected_entropy = wizard.slip39.bip39_to_entropy(BIP39_FIXTURE)
        for selected in combinations(payloads, 2):
            with self.subTest(selected=selected):
                self.assertEqual(
                    wizard.slip39.combine(list(selected)),
                    expected_entropy,
                )
        self.assertNotIn("verification failed", output.getvalue())
        self.assertIn(
            "Verified every threshold combination",
            output.getvalue(),
        )

    def test_wizard_encryption_rejects_non_tty_before_reading_file(self):
        output = io.StringIO()
        with mock.patch.object(
            sys.stdin,
            "isatty",
            return_value=False,
        ), mock.patch.object(
            wizard,
            "_ask",
        ) as ask, contextlib.redirect_stdout(output):
            wizard._wizard_encrypt()

        ask.assert_not_called()
        self.assertIn("requires a TTY", output.getvalue())

    def test_wizard_encryption_rejects_empty_passphrase(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "report.txt"
            source.write_bytes(b"synthetic report")
            output = io.StringIO()
            with mock.patch.object(
                sys.stdin,
                "isatty",
                return_value=True,
            ), mock.patch.object(
                wizard,
                "_ask",
                return_value=str(source),
            ), mock.patch(
                "getpass.getpass",
                return_value="",
            ), mock.patch.object(
                wizard.safeio,
                "atomic_write_bytes",
            ) as write, contextlib.redirect_stdout(output):
                wizard._wizard_encrypt()

        write.assert_not_called()
        self.assertIn("Empty passphrase", output.getvalue())

    def test_fordefi_encryption_validates_and_double_enters_phrase(self):
        output = io.StringIO()
        with mock.patch.object(
            sys.stdin,
            "isatty",
            return_value=True,
        ), mock.patch(
            "getpass.getpass",
            side_effect=[
                FORDEFI_PHRASE,
                FORDEFI_PHRASE.replace("lima", "mike"),
            ],
        ), mock.patch.object(
            wizard.safeio,
            "atomic_write_bytes",
        ) as write, contextlib.redirect_stdout(output):
            wizard._wizard_encrypt(fordefi_mode=True)

        write.assert_not_called()
        self.assertIn("entries do not match", output.getvalue())

    def test_guided_encryption_defaults_to_shen_extension(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "report.txt"
            source.write_bytes(b"synthetic report")

            def answer(prompt, default=""):
                if prompt == "File to encrypt":
                    return str(source)
                return default

            with mock.patch.object(
                sys.stdin,
                "isatty",
                return_value=True,
            ), mock.patch.object(
                wizard,
                "_ask",
                side_effect=answer,
            ), mock.patch(
                "getpass.getpass",
                side_effect=["synthetic passphrase", "synthetic passphrase"],
            ), mock.patch.object(
                wizard.core,
                "encrypt",
                return_value="synthetic-ciphertext",
            ), mock.patch.object(
                wizard.safeio,
                "atomic_write_bytes",
            ) as write, contextlib.redirect_stdout(io.StringIO()):
                wizard._wizard_encrypt()

        self.assertEqual(write.call_args.args[0], "secret.shen")


class TestCustodyDocumentation(unittest.TestCase):
    def test_station70_routes_are_distinguished(self):
        custody = (
            ROOT / "docs" / "CUSTODY-PATTERNS.md"
        ).read_text(encoding="utf-8")
        for expected in (
            "Native Fordefi/Bunker integration",
            "Bunker Custom Upload",
            "SWAT",
            "Station70 holds SHEN or one SHRD file",
            "backup-private-keys-station70",
            "custom-upload-overview",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, custody)

    def test_agents_md_is_the_single_ai_entry_point(self):
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        self.assertIn("`AGENTS.md` is the AI guidance entry point", agents)
        self.assertIn("`AGENTS.txt` or `LLMS.txt` is unnecessary", agents)
        self.assertIn("duplicate `AGENTS.txt` and `LLMS.txt`", readme)
        self.assertFalse((ROOT / "AGENTS.txt").exists())
        self.assertFalse((ROOT / "LLMS.txt").exists())


if __name__ == "__main__":
    unittest.main()
