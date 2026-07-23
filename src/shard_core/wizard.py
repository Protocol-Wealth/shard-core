"""Interactive guided mode — for people who don't want to learn flags.

Launched by running `shard-core` with no arguments (or `shard-core wizard`).
Covers the common flows: split a recovery phrase / secret into shares, recover
from shares, and passphrase encrypt/decrypt. Self-contained (imports only
``core`` and ``slip39``) to avoid a cycle with ``cli``.
"""

from __future__ import annotations

import getpass
import os
from pathlib import Path

from . import core, slip39


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


def _write_600(path: str, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _payload(path: str) -> str:
    lines = [
        ln.strip()
        for ln in Path(path).read_text().splitlines()
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
    print("  1) Split a recovery phrase / secret into shares")
    print("  2) Recover a phrase / secret from shares")
    print("  3) Encrypt a file with a passphrase")
    print("  4) Decrypt a file")
    choice = _ask("Choose 1-4", "1")
    if choice == "1":
        _wizard_split()
    elif choice == "2":
        _wizard_recover()
    elif choice == "3":
        _wizard_encrypt()
    elif choice == "4":
        _wizard_decrypt()
    else:
        print("Nothing to do.")


def _read_secret() -> bytes:
    print("\nHow will you provide the secret/phrase?")
    print("  1) Read it from a file (recommended)")
    print("  2) Type or paste it now (hidden)")
    if _ask("Choose 1-2", "1") == "2":
        return getpass.getpass("Paste the phrase (hidden): ").encode()
    return Path(_ask("Path to the file")).read_bytes().rstrip(b"\r\n")


def _wizard_split() -> None:
    secret = _read_secret()
    if not secret:
        print("Empty secret — nothing to do.")
        return
    n = _ask_int("How many shares total (e.g. 4 = you + Adam + Jason + Coincover)", 4)
    t = _ask_int("How many needed to recover (threshold, e.g. 2 or 3)", 2)
    suggested = (["nick", "adam", "jason", "coincover"] + [f"s{i}" for i in range(5, 65)])[:n]
    labels = _ask("Labels for each share (comma-separated)", ",".join(suggested)).split(",")
    labels = [x.strip() for x in labels]
    if len(labels) != n:
        print(f"  {len(labels)} labels for {n} shares — adjust and retry.")
        return
    out = _ask("Output folder", "shares")

    use_slip39 = False
    if slip39.available():
        use_slip39 = _yn("Use SLIP-39 word-list shares (recommended for seed phrases)?", True)
    else:
        print("  (SLIP-39 not installed — using encrypted shards. For word lists:")
        print("   pip install 'shard-core[slip39]')")

    Path(out).mkdir(parents=True, exist_ok=True)
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

    written = []
    for i, (body, label) in enumerate(zip(payloads, labels), start=1):
        path = os.path.join(out, f"share-{label}.txt")
        comment = f"# shard-core {kind} {t}-of-{n} share {i}/{n} [{label}]\n"
        _write_600(path, (comment + body + "\n").encode())
        written.append(path)

    print(f"\nWrote {n} shares (any {t} reconstruct):")
    for p in written:
        print(f"  {p}")
    print("\nNext steps:")
    print("  - Give one share to each holder; store them in separate places.")
    print("  - Coincover just stores its share and cannot use it alone.")
    print("  - To recover later, run the wizard again and choose 'Recover'.")


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
    payloads = [_payload(f) for f in files]
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
            _write_600(out, text + b"\n")
        except Exception as exc:
            print(f"Recovery failed: {exc}")
            return
    else:
        try:
            secret = core.recover(payloads)
        except Exception as exc:
            print(f"Recovery failed: {exc}")
            return
        _write_600(out, secret)
    print(f"\nRecovered -> {out}")


def _wizard_encrypt() -> None:
    data = Path(_ask("File to encrypt")).read_bytes()
    pw = getpass.getpass("Passphrase: ")
    if getpass.getpass("Confirm passphrase: ") != pw:
        print("Passphrases do not match.")
        return
    out = _ask("Write encrypted file to", "secret.enc")
    _write_600(out, (core.encrypt(data, pw.encode()) + "\n").encode())
    print(f"Encrypted -> {out}")


def _wizard_decrypt() -> None:
    blob = Path(_ask("Encrypted file")).read_text().strip()
    pw = getpass.getpass("Passphrase: ")
    out = _ask("Write decrypted file to", "secret.out")
    try:
        data = core.decrypt(blob, pw.encode())
    except ValueError:
        print("Decryption failed (wrong passphrase or corrupted file).")
        return
    _write_600(out, data)
    print(f"Decrypted -> {out}")
