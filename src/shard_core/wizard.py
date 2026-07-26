"""Interactive guided mode — for people who don't want to learn flags.

Launched by running `shard-core` with no arguments (or `shard-core wizard`).
Covers the common flows: split a recovery phrase / secret into shares, recover
from shares, and passphrase encrypt/decrypt. Self-contained (imports only
``core`` and ``slip39``) to avoid a cycle with ``cli``.
"""

from __future__ import annotations

import getpass
import os
import sys
from itertools import combinations
from pathlib import Path

from . import core, fordefi as fordefi_support, safeio, slip39


def _ask(prompt: str, default: str = "") -> str:
    hint = f" [{default}]" if default else ""
    try:
        val = input(f"{prompt}{hint}: ").strip()
    except EOFError:
        val = ""
    return val or default


def _ask_int(prompt: str, default: int) -> int:
    while True:
        raw = _ask(prompt, str(default))
        try:
            return int(raw)
        except ValueError:
            print("  please enter a whole number")


def _yn(prompt: str, default: bool = True) -> bool:
    raw = _ask(prompt + (" (Y/n)" if default else " (y/N)"))
    if not raw:
        return default
    return raw.lower().startswith("y")


def _read_error(path: str, exc: Exception) -> None:
    """Report an unreadable file in one line — never a traceback at a prompt."""
    reason = getattr(exc, "strerror", None) or str(exc)
    print(f"cannot read {path}: {reason}")


def _payload(path: str) -> str | None:
    """Return a share file's payload, or None if the file cannot be read."""
    try:
        text = Path(path).read_text()
    except (OSError, UnicodeDecodeError) as exc:
        _read_error(path, exc)
        return None
    lines = [
        ln.strip()
        for ln in text.splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]
    return " ".join(lines)


def _is_mnemonic(payload: str) -> bool:
    parts = payload.split()
    return len(parts) >= 20 and all(p.isalpha() for p in parts)


# --------------------------------------------------------------------------- #
def run_wizard() -> None:
    print("\nshard-core — guided mode")
    print("For real key material, run this on an OFFLINE / airgapped machine.\n")
    print("  1) Split a Fordefi recovery phrase (SHRD)")
    print("  2) Split another secret / confirmed BIP-39 phrase")
    print("  3) Recover a phrase / secret from shares")
    print("  4) Encrypt a file with a passphrase")
    print("  5) Decrypt a file")
    print("  6) Choose a custody route (provider / business / trusted people)")
    choice = _ask("Choose 1-6", "1")
    if choice == "1":
        _wizard_split(fordefi_mode=True)
    elif choice == "2":
        _wizard_split(fordefi_mode=False)
    elif choice == "3":
        _wizard_recover()
    elif choice == "4":
        _wizard_encrypt()
    elif choice == "5":
        _wizard_decrypt()
    elif choice == "6":
        _wizard_custody()
    else:
        print("Nothing to do.")


def _wizard_custody() -> None:
    print("\nChoose the protection and custody route before opening a secret:")
    print("  1) A confirmed provider-native workflow")
    print("  2) One SHEN encrypted file held by a provider or person")
    print("  3) SHRD threshold shares held by 2 or more independent parties")
    choice = _ask("Choose 1-3")

    if choice == "1":
        print("\nIdentify the exact provider method:")
        print("  1) CoinCover Key Vault CLI")
        print("  2) Fordefi managed CoinCover Public Key Upload")
        print("  3) Station70 native Fordefi/Bunker")
        print("  4) Station70 Bunker Custom Upload")
        print("  5) Station70 SWAT")
        print("  6) Another confirmed provider-native method")
        method = _ask("Choose 1-6")
        if method not in {"1", "2", "3", "4", "5", "6"}:
            print("Nothing to do.")
            return
        print("\nNo shard-core artifact will be created.")
        print("Cancel any shard-core encryption prompt. Use the provider's current")
        print("official console, CLI, wallet integration, and agreement for its")
        print("required input, encryption, credentials, upload, and recovery procedure.")
        print("shard-core never requests provider API credentials or performs an upload.")
        return

    if choice == "2":
        print("\nFirst confirm that the holder accepts and returns an opaque SHEN")
        print("Base64 text file byte-for-byte, and assign its wrapping credential")
        print("to a separately approved path.")
        if not _yn("Has the holder confirmed those requirements?", False):
            print("Stop and obtain the holder's written format and release requirements.")
            return
        fordefi_mode = _yn(
            "Is the protected material a Fordefi Recovery Phrase?",
            False,
        )
        _wizard_encrypt(fordefi_mode=fordefi_mode)
        return

    if choice == "3":
        print("\nEach provider, business, or trusted person receives one SHRD file.")
        print("Confirm every external holder accepts and returns that exact file.")
        print("A 2-of-2 policy has no loss tolerance; 2-of-3 tolerates one unavailable holder.")
        if not _yn(
            "Have all holders confirmed their custody and release requirements?",
            False,
        ):
            print("Stop and obtain every holder's written custody and release requirements.")
            return
        fordefi_mode = _yn(
            "Is the protected material a Fordefi Recovery Phrase?",
            False,
        )
        _wizard_split(
            fordefi_mode=fordefi_mode,
            allow_slip39=False,
        )
        return

    print("Nothing to do.")


def _read_secret() -> bytes:
    print("\nHow will you provide the secret/phrase?")
    print("  1) Read it from a file (recommended)")
    print("  2) Type or paste it now (hidden)")
    if _ask("Choose 1-2", "1") == "2":
        if not sys.stdin.isatty():
            print("Interactive secret entry requires a TTY.")
            return b""
        return getpass.getpass("Paste the phrase (hidden): ").encode()
    path = _ask("Path to the file")
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        _read_error(path, exc)
        return b""


def _read_fordefi_secret() -> bytes | None:
    """Read and validate a Fordefi phrase twice without echoing it."""
    if not sys.stdin.isatty():
        print("Interactive Fordefi phrase entry requires a TTY.")
        return None
    try:
        secret = fordefi_support.canonicalize_recovery_phrase(
            getpass.getpass("Fordefi recovery phrase: ")
        )
        confirmation = fordefi_support.canonicalize_recovery_phrase(
            getpass.getpass("Confirm Fordefi recovery phrase: ")
        )
    except ValueError as exc:
        print(f"Invalid Fordefi recovery phrase: {exc}")
        return None
    if confirmation != secret:
        print("Fordefi recovery phrase entries do not match.")
        return None
    return secret


def _wizard_split(
    *,
    fordefi_mode: bool = False,
    allow_slip39: bool = True,
) -> None:
    print("\nThis splits your secret into shares:")
    print("  - One below-threshold share cannot reveal the plaintext.")
    print("  - Share headers and ciphertext length still expose limited metadata.")
    print("  - The secret stays encrypted until enough shares are combined.")
    print("  - You choose the threshold: how many shares are needed to unlock it.\n")
    if fordefi_mode:
        secret = _read_fordefi_secret()
        if secret is None:
            return
    else:
        secret = _read_secret()
    if not secret:
        print("Empty secret — nothing to do.")
        return
    n = _ask_int("How many shares in total", 5)
    if n < 2:
        print("  You need at least 2 shares.")
        return
    if n == 2:
        t = 2
        print("With 2 shares, BOTH are required to unlock (2-of-2).")
    else:
        t = _ask_int(f"How many shares needed to unlock (2 to {n})", 2)
        if t < 2:
            print("  Threshold must be at least 2 (a single share must never unlock the secret).")
            return
        if t > n:
            print("  Threshold cannot exceed the total number of shares.")
            return
    raw = _ask("Optional labels (comma-separated), or press Enter for numbers", "")
    labels = core.normalize_labels(raw.split(",") if raw else [], n)
    out = _ask(
        "Output folder",
        "fordefi-shares" if fordefi_mode else "shares",
    )

    use_slip39 = False
    if not fordefi_mode and allow_slip39 and slip39.available():
        use_slip39 = _yn("Use SLIP-39 word-list shares (recommended for seed phrases)?", True)
    elif not fordefi_mode and allow_slip39:
        print("  (SLIP-39 not installed — using encrypted shards. For word lists:")
        print("   pip install 'shard-core[slip39]')")

    if use_slip39:
        try:
            payloads = slip39.split_bip39(secret.decode(), t, n)
            kind = "slip39"
        except Exception:
            print("  (not a valid BIP-39 phrase — using encrypted shards instead)")
            payloads = core.protect(secret, t, n)
            kind = "protect"
    else:
        payloads = core.protect(secret, t, n)
        kind = "protect"

    if kind == "protect":
        try:
            verification = core.verify_complete_set(payloads)
            if not verification.ok:
                raise RuntimeError("not every threshold combination authenticated")
            for selected in combinations(range(n), t):
                if core.recover([payloads[index] for index in selected]) != secret:
                    raise RuntimeError("round-trip plaintext mismatch")
        except (RuntimeError, ValueError) as exc:
            print(f"Internal share-set self-test failed: {exc}")
            print("No files were written.")
            return

    output_dir = Path(out)
    paths = [output_dir / f"share-{label}.txt" for label in labels]
    try:
        safeio.preflight_output_paths(paths)
        written = []
        for i, (body, label, path) in enumerate(
            zip(payloads, labels, paths),
            start=1,
        ):
            if kind == "protect":
                version = core.parse_shard(body)["version"]
                mode = "fordefi" if fordefi_mode else "protect"
                comment = (
                    f"# shard-core SHRD-v{version} {mode} "
                    f"{t}-of-{n} share {i}/{n} [{label}]\n"
                )
            else:
                comment = (
                    f"# shard-core SLIP-39 bip39 "
                    f"{t}-of-{n} share {i}/{n} [{label}]\n"
                )
            safeio.atomic_write_bytes(path, (comment + body + "\n").encode())
            written.append(str(path))
    except (OSError, ValueError) as exc:
        print(f"Cannot write share set: {exc}")
        return

    try:
        written_payloads = []
        for path in paths:
            payload = _payload(str(path))
            if payload is None:
                raise RuntimeError("a written share could not be read back")
            written_payloads.append(payload)
        verification = core.verify_complete_set(written_payloads)
        if not verification.ok:
            raise RuntimeError("not every written threshold combination authenticated")
        for selected in combinations(range(n), t):
            if core.recover(
                [written_payloads[index] for index in selected]
            ) != secret:
                raise RuntimeError("written share round-trip plaintext mismatch")
    except (RuntimeError, ValueError) as exc:
        print(f"Written share-set verification failed: {exc}")
        print("Do not distribute the written files.")
        return

    print("Verified every threshold combination from the written share files.")
    print(
        f"\nWrote {n} shares. Any {t} together rebuild the secret; "
        f"fewer than {t} cannot decrypt the plaintext."
    )
    for p in written:
        print(f"  {p}")
    print("\nNext steps:")
    print("  - Give ONE share to each holder; store them in separate places.")
    print("  - A holder who only stores one share cannot recover the plaintext alone.")
    print("  - To rebuild later, run this wizard again and choose 'Recover'.")


def _wizard_recover() -> None:
    print("\nEnter the share files, one per line (blank line to finish).")
    files: list[str] = []
    while True:
        f = _ask("Share file")
        if not f:
            break
        files.append(f)
    if not files:
        print("No shares given.")
        return
    payloads = []
    for f in files:
        body = _payload(f)
        if body is None:
            return
        payloads.append(body)
    out = _ask("Write the recovered secret to", "recovered.txt")

    if _is_mnemonic(payloads[0]):
        if not slip39.available():
            print("These are SLIP-39 shares. Install: pip install 'shard-core[slip39]'")
            return
        try:
            secret = slip39.combine(payloads)
            try:
                text = slip39.entropy_to_bip39(secret).encode()
            except Exception:
                text = secret
            safeio.atomic_write_bytes(out, text + b"\n")
        except Exception as exc:
            print(f"Recovery failed: {exc}")
            return
    else:
        try:
            secret = core.recover(payloads)
        except Exception as exc:
            print(f"Recovery failed: {exc}")
            return
        try:
            safeio.atomic_write_bytes(out, secret)
        except (OSError, ValueError) as exc:
            print(f"Cannot write recovered secret: {exc}")
            return
    print(f"\nRecovered -> {out}")


def _wizard_encrypt(*, fordefi_mode: bool = False) -> None:
    if not sys.stdin.isatty():
        print("Interactive encryption requires a TTY.")
        return
    if fordefi_mode:
        data = _read_fordefi_secret()
        if data is None:
            return
    else:
        path = _ask("File to encrypt")
        try:
            data = Path(path).read_bytes()
        except OSError as exc:
            _read_error(path, exc)
            return
    pw = getpass.getpass("Passphrase: ")
    if not pw:
        print("Empty passphrase — nothing to do.")
        return
    pw_bytes = pw.encode()
    if len(pw_bytes) > 4096:
        print("Passphrase is too large — nothing to do.")
        return
    if getpass.getpass("Confirm passphrase: ") != pw:
        print("Passphrases do not match.")
        return
    out = _ask(
        "Write encrypted file to",
        "fordefi-phrase.shen" if fordefi_mode else "secret.shen",
    )
    try:
        safeio.atomic_write_bytes(
            out,
            (core.encrypt(data, pw_bytes) + "\n").encode(),
        )
    except (OSError, ValueError) as exc:
        print(f"Cannot write encrypted file: {exc}")
        return
    print(f"Encrypted -> {out}")


def _wizard_decrypt() -> None:
    path = _ask("Encrypted file")
    try:
        blob = Path(path).read_text().strip()
    except (OSError, UnicodeDecodeError) as exc:
        _read_error(path, exc)
        return
    pw = getpass.getpass("Passphrase: ")
    out = _ask("Write decrypted file to", "secret.out")
    try:
        data = core.decrypt(blob, pw.encode())
    except ValueError:
        print("Decryption failed (wrong passphrase or corrupted file).")
        return
    try:
        safeio.atomic_write_bytes(out, data)
    except (OSError, ValueError) as exc:
        print(f"Cannot write decrypted file: {exc}")
        return
    print(f"Decrypted -> {out}")
