"""shard-core command-line interface.

Subcommands:
  encrypt / decrypt   passphrase-based AEAD (one ciphertext blob)
  protect / recover   encrypt + Shamir n-of-m sharding
  info                inspect a shard's header without reconstructing
  fordefi split/combine   guided wrapper for a Fordefi recovery phrase
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from . import __version__, core, slip39

DEFAULT_FORDEFI_LABELS = "coincover,bitwarden,offline"


# --------------------------------------------------------------------------- #
# I/O helpers
# --------------------------------------------------------------------------- #
def _read_input(path: str | None) -> bytes:
    if path in (None, "-"):
        return sys.stdin.buffer.read()
    return Path(path).read_bytes()


def _write_secret(path: str | None, data: bytes) -> None:
    """Write recovered plaintext. To a file it is created 0600 up front."""
    if path in (None, "-"):
        sys.stdout.buffer.write(data)
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _write_text(path: str | None, text: str) -> None:
    if path in (None, "-"):
        sys.stdout.write(text)
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)


def _get_passphrase(args, confirm: bool) -> bytes:
    if getattr(args, "passphrase_env", None):
        val = os.environ.get(args.passphrase_env)
        if val is None:
            sys.exit(f"error: env var {args.passphrase_env} is not set")
        return val.encode()
    if getattr(args, "passphrase_file", None):
        return Path(args.passphrase_file).read_bytes().rstrip(b"\r\n")
    pw = getpass.getpass("Passphrase: ")
    if not pw:
        sys.exit("error: empty passphrase")
    if confirm and getpass.getpass("Confirm passphrase: ") != pw:
        sys.exit("error: passphrases do not match")
    return pw.encode()


def _shard_comment(mode: str, k: int, n: int, i: int, label: str | None) -> str:
    tag = f" [{label}]" if label else ""
    return f"# shard-core v1 {mode} {k}-of-{n} share {i}/{n}{tag}\n"


def _read_shard_file(path: str) -> str:
    """Return the base64 payload from a shard file (ignores comment/blank lines)."""
    lines = Path(path).read_text().splitlines()
    body = [ln.strip() for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]
    if not body:
        sys.exit(f"error: no shard payload found in {path}")
    return "".join(body)


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def _cmd_encrypt(args) -> None:
    secret = _read_input(args.input)
    blob = core.encrypt(secret, _get_passphrase(args, confirm=True), n_log2=args.scrypt_n)
    _write_text(args.output, blob + "\n")


def _cmd_decrypt(args) -> None:
    blob = _read_input(args.input).decode("ascii").strip()
    try:
        secret = core.decrypt(blob, _get_passphrase(args, confirm=False))
    except ValueError:
        sys.exit("error: decryption failed (wrong passphrase or corrupted data)")
    _write_secret(args.output, secret)


def _do_protect(secret: bytes, threshold: int, shares: int, out_dir: str, labels: list[str], mode: str) -> None:
    if len(labels) != shares:
        sys.exit(f"error: {len(labels)} label(s) for {shares} shares")
    shard_b64 = core.protect(secret, threshold, shares)
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    written = []
    for i, (b64, label) in enumerate(zip(shard_b64, labels), start=1):
        name = f"share-{label}.txt"
        path = os.path.join(out_dir, name)
        _write_text(path, _shard_comment(mode, threshold, shares, i, label) + b64 + "\n")
        written.append(path)
    print(f"wrote {shares} shard(s), any {threshold} reconstruct:")
    for p in written:
        print(f"  {p}")
    print("\nEach shard is self-contained and reveals NOTHING on its own.")
    print("Store shards in separate places; keep fewer than the threshold in any one place.")


def _cmd_protect(args) -> None:
    secret = _read_input(args.input)
    labels = args.labels.split(",") if args.labels else [f"{i:02d}" for i in range(1, args.shares + 1)]
    _do_protect(secret, args.threshold, args.shares, args.out_dir, labels, "protect")


def _cmd_recover(args) -> None:
    shard_b64 = [_read_shard_file(p) for p in args.shards]
    try:
        secret = core.recover(shard_b64)
    except ValueError as exc:
        sys.exit(f"error: {exc}")
    _write_secret(args.output, secret)


def _cmd_info(args) -> None:
    meta = core.parse_shard(_read_shard_file(args.shard))
    print(
        f"mode=protect version={meta['version']} "
        f"threshold={meta['threshold']} shares={meta['shares']} index={meta['index']} "
        f"ciphertext_bytes={len(meta['ciphertext'])}"
    )


def _cmd_fordefi_split(args) -> None:
    phrase = _read_input(args.phrase_file) if args.phrase_file else getpass.getpass(
        "Fordefi recovery phrase: "
    ).encode()
    phrase = phrase.rstrip(b"\r\n")
    if not phrase:
        sys.exit("error: empty recovery phrase")
    labels = args.labels.split(",")
    if args.slip39:
        try:
            mnemonics = slip39.split_bip39(phrase.decode(), args.threshold, args.shares)
        except Exception as exc:
            sys.exit(f"error: {exc}\n(the phrase must be a valid BIP-39 mnemonic for SLIP-39; "
                     f"otherwise omit --slip39 to use AEAD+Shamir shards)")
        _do_slip39_split(mnemonics, args.out_dir, labels, "fordefi", args.threshold, args.shares, "bip39")
    else:
        _do_protect(phrase, args.threshold, args.shares, args.out_dir, labels, "fordefi")
    print("\nFordefi: distribute one shard per location (e.g. coincover / bitwarden / offline).")
    print("Coincover is storage-only and cannot decrypt a shard; the threshold stays with you.")
    print("To recover the phrase later: `shard-core fordefi combine ...` (offline), then feed it")
    print("to Fordefi's recovery-tool. Do this only on an airgapped machine.")


def _cmd_fordefi_combine(args) -> None:
    if args.slip39:
        mnemonics = [_read_mnemonic_file(p) for p in args.shards]
        try:
            phrase = slip39.entropy_to_bip39(slip39.combine(mnemonics)).encode()
        except Exception as exc:
            sys.exit(f"error: {exc}")
    else:
        shard_b64 = [_read_shard_file(p) for p in args.shards]
        try:
            phrase = core.recover(shard_b64)
        except ValueError as exc:
            sys.exit(f"error: {exc}")
    _write_secret(args.output, phrase)


# --------------------------------------------------------------------------- #
# SLIP-39 (optional; needs the `slip39` extra)
# --------------------------------------------------------------------------- #
def _slip39_passphrase(args) -> bytes:
    if getattr(args, "passphrase_env", None):
        val = os.environ.get(args.passphrase_env)
        if val is None:
            sys.exit(f"error: env var {args.passphrase_env} is not set")
        return val.encode()
    if getattr(args, "passphrase_file", None):
        return Path(args.passphrase_file).read_bytes().rstrip(b"\r\n")
    return b""


def _read_mnemonic_file(path: str) -> str:
    lines = Path(path).read_text().splitlines()
    words = " ".join(ln.strip() for ln in lines if ln.strip() and not ln.lstrip().startswith("#"))
    return " ".join(words.split())


def _write_mnemonic_share(out_dir, label, mnemonic, mode, k, n, i, source) -> str:
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    path = os.path.join(out_dir, f"share-{label}.txt")
    tag = f" [{label}]" if label else ""
    comment = f"# shard-core v1 {mode}({source}) SLIP-39 {k}-of-{n} share {i}/{n}{tag}\n"
    _write_text(path, comment + mnemonic + "\n")
    return path


def _do_slip39_split(mnemonics, out_dir, labels, mode, k, n, source) -> None:
    if len(labels) != n:
        sys.exit(f"error: {len(labels)} label(s) for {n} shares")
    written = [
        _write_mnemonic_share(out_dir, label, mn, mode, k, n, i, source)
        for i, (mn, label) in enumerate(zip(mnemonics, labels), start=1)
    ]
    print(f"wrote {n} SLIP-39 share(s), any {k} reconstruct:")
    for p in written:
        print(f"  {p}")
    print("\nEach share is a checksummed SLIP-39 word list; store one per location.")


def _cmd_slip39_split(args) -> None:
    provided = [bool(args.bip39_file), bool(args.hex), bool(args.secret_file)]
    if sum(provided) != 1:
        sys.exit("error: provide exactly one of --bip39-file / --hex / --secret-file")
    pw = _slip39_passphrase(args)
    labels = args.labels.split(",") if args.labels else [f"{i:02d}" for i in range(1, args.shares + 1)]
    try:
        if args.bip39_file:
            phrase = Path(args.bip39_file).read_text().strip()
            mnemonics, source = slip39.split_bip39(phrase, args.threshold, args.shares, pw), "bip39"
        elif args.hex:
            secret = bytes.fromhex(args.hex)
            mnemonics, source = slip39.split_master_secret(secret, args.threshold, args.shares, pw), "hex"
        else:
            secret = Path(args.secret_file).read_bytes()
            mnemonics, source = slip39.split_master_secret(secret, args.threshold, args.shares, pw), "raw"
    except Exception as exc:
        sys.exit(f"error: {exc}")
    _do_slip39_split(mnemonics, args.out_dir, labels, "slip39", args.threshold, args.shares, source)


def _cmd_slip39_combine(args) -> None:
    pw = _slip39_passphrase(args)
    mnemonics = [_read_mnemonic_file(p) for p in args.shares]
    try:
        secret = slip39.combine(mnemonics, pw)
    except Exception as exc:
        sys.exit(f"error: {exc}")
    if args.bip39:
        _write_text(args.output, slip39.entropy_to_bip39(secret) + "\n")
    elif args.hex:
        _write_text(args.output, secret.hex() + "\n")
    else:
        _write_secret(args.output, secret)


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def _add_passphrase_opts(p: argparse.ArgumentParser) -> None:
    p.add_argument("--passphrase-env", metavar="VAR", help="read passphrase from an env var")
    p.add_argument("--passphrase-file", metavar="FILE", help="read passphrase from a file")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shard-core",
        description="Local, offline encryption + Shamir n-of-m secret sharing. No network, ever.",
    )
    parser.add_argument("--version", action="version", version=f"shard-core {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encrypt", help="passphrase-encrypt a secret (AEAD)")
    enc.add_argument("-i", "--input", default="-", help="input file, or - for stdin")
    enc.add_argument("-o", "--output", default="-", help="output file, or - for stdout")
    enc.add_argument("--scrypt-n", type=int, default=core.DEFAULT_SCRYPT_N_LOG2,
                     dest="scrypt_n", metavar="LOG2", help="scrypt cost as log2(N) (default 17)")
    _add_passphrase_opts(enc)
    enc.set_defaults(func=_cmd_encrypt)

    dec = sub.add_parser("decrypt", help="passphrase-decrypt a secret")
    dec.add_argument("-i", "--input", default="-", help="input file, or - for stdin")
    dec.add_argument("-o", "--output", default="-", help="output file, or - for stdout")
    _add_passphrase_opts(dec)
    dec.set_defaults(func=_cmd_decrypt)

    pro = sub.add_parser("protect", help="encrypt + Shamir-split into n-of-m shards")
    pro.add_argument("-t", "--threshold", type=int, required=True, help="shards needed to recover (k)")
    pro.add_argument("-n", "--shares", type=int, required=True, help="total shards (m)")
    pro.add_argument("-i", "--input", default="-", help="secret file, or - for stdin")
    pro.add_argument("-o", "--out-dir", default="shards", dest="out_dir", help="output directory")
    pro.add_argument("--labels", help="comma-separated labels (one per shard)")
    pro.set_defaults(func=_cmd_protect)

    rec = sub.add_parser("recover", help="reconstruct a secret from shards")
    rec.add_argument("-o", "--output", default="-", help="output file, or - for stdout")
    rec.add_argument("shards", nargs="+", help="shard files (>= threshold)")
    rec.set_defaults(func=_cmd_recover)

    inf = sub.add_parser("info", help="show a shard's header without reconstructing")
    inf.add_argument("shard", help="a shard file")
    inf.set_defaults(func=_cmd_info)

    fd = sub.add_parser("fordefi", help="guided Fordefi recovery-phrase workflow")
    fdsub = fd.add_subparsers(dest="fordefi_command", required=True)

    fds = fdsub.add_parser("split", help="shard a Fordefi recovery phrase")
    fds.add_argument("-t", "--threshold", type=int, default=2, help="shards needed (default 2)")
    fds.add_argument("-n", "--shares", type=int, default=3, help="total shards (default 3)")
    fds.add_argument("--phrase-file", help="file with the phrase (else prompt)")
    fds.add_argument("--labels", default=DEFAULT_FORDEFI_LABELS, help="comma-separated labels")
    fds.add_argument("-o", "--out-dir", default="fordefi-shards", dest="out_dir", help="output directory")
    fds.add_argument("--slip39", action="store_true",
                     help="emit SLIP-39 word-list shares (phrase must be valid BIP-39)")
    fds.set_defaults(func=_cmd_fordefi_split)

    fdc = fdsub.add_parser("combine", help="recover a Fordefi recovery phrase")
    fdc.add_argument("-o", "--output", default="-", help="output file, or - for stdout")
    fdc.add_argument("shards", nargs="+", help="shard files (>= threshold)")
    fdc.add_argument("--slip39", action="store_true", help="shards are SLIP-39 word lists")
    fdc.set_defaults(func=_cmd_fordefi_combine)

    s39 = sub.add_parser("slip39", help="SLIP-39 word-list shares (needs the 'slip39' extra)")
    s39sub = s39.add_subparsers(dest="slip39_command", required=True)

    s39s = s39sub.add_parser("split", help="split a 16/32-byte secret or BIP-39 phrase into SLIP-39 shares")
    s39s.add_argument("-t", "--threshold", type=int, required=True, help="shares needed (k)")
    s39s.add_argument("-n", "--shares", type=int, required=True, help="total shares (m)")
    s39s.add_argument("--bip39-file", help="file with a BIP-39 recovery phrase")
    s39s.add_argument("--hex", help="master secret as hex (16/20/24/28/32 bytes)")
    s39s.add_argument("--secret-file", help="raw master-secret file (16/20/24/28/32 bytes)")
    s39s.add_argument("--labels", help="comma-separated labels")
    s39s.add_argument("-o", "--out-dir", default="slip39-shares", dest="out_dir", help="output directory")
    _add_passphrase_opts(s39s)
    s39s.set_defaults(func=_cmd_slip39_split)

    s39c = s39sub.add_parser("combine", help="reconstruct a secret from SLIP-39 shares")
    s39c.add_argument("shares", nargs="+", help="SLIP-39 share files (>= threshold)")
    s39c.add_argument("-o", "--output", default="-", help="output file, or - for stdout")
    s39c.add_argument("--bip39", action="store_true", help="output as a BIP-39 phrase")
    s39c.add_argument("--hex", action="store_true", help="output as hex")
    _add_passphrase_opts(s39c)
    s39c.set_defaults(func=_cmd_slip39_combine)

    wiz = sub.add_parser("wizard", help="interactive guided mode (also runs with no arguments)")
    wiz.set_defaults(func=_cmd_wizard)

    return parser


def _cmd_wizard(args) -> None:
    from .wizard import run_wizard

    run_wizard()


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:  # no arguments -> friendly guided mode
        from .wizard import run_wizard

        run_wizard()
        return
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
