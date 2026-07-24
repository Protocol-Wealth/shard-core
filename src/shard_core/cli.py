"""shard-core command-line interface.

Subcommands:
  encrypt / decrypt   passphrase-based AEAD (one ciphertext blob)
  protect / recover   encrypt + Shamir n-of-m sharding
  info                inspect a shard's header without reconstructing
  fordefi split/combine   guided wrapper for a Fordefi recovery phrase
"""

from __future__ import annotations

import argparse
import base64
import getpass
import os
import secrets
import stat
import sys
from itertools import combinations
from pathlib import Path

from . import __version__, core, fordefi as fordefi_support, manifest, safeio, slip39

MAX_PASSPHRASE_BYTES = 4096


# --------------------------------------------------------------------------- #
# I/O helpers
# --------------------------------------------------------------------------- #
def _read_input(path: str | None) -> bytes:
    if path in (None, "-"):
        return sys.stdin.buffer.read()
    return Path(path).read_bytes()


def _emit_secret(args, data: bytes) -> None:
    """Emit plaintext only to an explicitly selected destination."""
    if args.stdout:
        if getattr(args, "force", False):
            raise ValueError("--force cannot be used with --stdout")
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        return

    if args.output == "-":
        raise ValueError("use --stdout to write sensitive plaintext to stdout")

    safeio.atomic_write_bytes(
        args.output,
        data,
        force=getattr(args, "force", False),
    )


def _write_text(path: str | None, text: str, *, force: bool = False) -> None:
    if path in (None, "-"):
        sys.stdout.write(text)
        sys.stdout.flush()
        return
    safeio.atomic_write_text(path, text, force=force)


def _require_nonempty_secret(value: bytes, *, source: str) -> bytes:
    value = value.rstrip(b"\r\n")
    if not value:
        raise ValueError(f"empty passphrase from {source}")
    if len(value) > MAX_PASSPHRASE_BYTES:
        raise ValueError(f"passphrase from {source} is too large")
    return value


def _read_passphrase_file(path: str, *, allow_insecure: bool) -> bytes:
    target = Path(path)
    if not allow_insecure:
        metadata = os.lstat(target)
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"refusing symlink passphrase file: {target}")
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"passphrase file is not regular: {target}")
        if os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError(
                f"passphrase file is group/world accessible: {target}; "
                "use chmod 600 or --allow-insecure-passphrase-file"
            )

    value = safeio.read_limited_bytes(
        target,
        max_bytes=MAX_PASSPHRASE_BYTES,
        allow_symlink=allow_insecure,
    )
    return _require_nonempty_secret(value, source=f"file {target}")


def _get_passphrase(args, confirm: bool) -> bytes:
    if getattr(args, "passphrase_env", None):
        val = os.environ.get(args.passphrase_env)
        if val is None:
            raise ValueError(f"env var {args.passphrase_env} is not set")
        print(
            "warning: environment-variable passphrases may be visible "
            "to same-user processes and child processes",
            file=sys.stderr,
        )
        return _require_nonempty_secret(
            val.encode(),
            source=f"environment variable {args.passphrase_env}",
        )
    if getattr(args, "passphrase_file", None):
        return _read_passphrase_file(
            args.passphrase_file,
            allow_insecure=getattr(args, "allow_insecure_passphrase_file", False),
        )
    pw = _require_nonempty_secret(
        getpass.getpass("Passphrase: ").encode(),
        source="interactive prompt",
    )
    if confirm:
        confirmation = _require_nonempty_secret(
            getpass.getpass("Confirm passphrase: ").encode(),
            source="confirmation prompt",
        )
        if confirmation != pw:
            raise ValueError("passphrases do not match")
    return pw


def _shard_comment(
    mode: str,
    k: int,
    n: int,
    i: int,
    label: str | None,
    *,
    version: int,
) -> str:
    tag = f" [{label}]" if label else ""
    return (
        f"# shard-core SHRD-v{version} "
        f"{mode} {k}-of-{n} share {i}/{n}{tag}\n"
    )


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
    _write_text(args.output, blob + "\n", force=args.force)


def _cmd_decrypt(args) -> None:
    blob = _read_input(args.input).decode("ascii").strip()
    try:
        secret = core.decrypt(blob, _get_passphrase(args, confirm=False))
    except ValueError:
        sys.exit("error: decryption failed (wrong passphrase or corrupted data)")
    _emit_secret(args, secret)


def _do_protect(
    secret: bytes,
    threshold: int,
    shares: int,
    out_dir: str,
    labels: list[str],
    mode: str,
    *,
    force: bool = False,
    manifest_path: str | None = None,
) -> None:
    labels = core.normalize_labels(labels, shares)
    shard_b64 = core.protect(secret, threshold, shares)
    verification = core.verify_complete_set(shard_b64)
    if not verification.ok:
        raise RuntimeError("internal self-test failed; no files were written")
    for selected in combinations(range(shares), threshold):
        recovered = core.recover([shard_b64[index] for index in selected])
        if recovered != secret:
            raise RuntimeError(
                "generated shard set failed round-trip verification; "
                "no files were written"
            )

    output_dir = Path(out_dir)
    paths = [
        output_dir / f"share-{label}.txt"
        for label in labels
    ]
    share_texts = []
    for index, (body, label) in enumerate(zip(shard_b64, labels), start=1):
        version = core.parse_shard(body)["version"]
        share_texts.append(
            _shard_comment(
                mode,
                threshold,
                shares,
                index,
                label,
                version=version,
            )
            + body
            + "\n"
        )

    manifest_target = Path(manifest_path) if manifest_path else None
    manifest_text = None
    if manifest_target is not None:
        document = manifest.build_shrd_manifest(
            shard_b64,
            labels=labels,
            filenames=[path.name for path in paths],
            file_contents=[text.encode("utf-8") for text in share_texts],
            git_commit=os.environ.get("SHARD_CORE_GIT_COMMIT", "unknown"),
        )
        manifest_text = manifest.dumps(document)

    destinations = list(paths)
    if manifest_target is not None:
        destinations.append(manifest_target)
    safeio.preflight_output_paths(destinations, force=force)
    written = []
    for text, path in zip(share_texts, paths):
        _write_text(str(path), text, force=force)
        written.append(str(path))
    if manifest_target is not None and manifest_text is not None:
        _write_text(str(manifest_target), manifest_text, force=force)
    print(f"wrote {shares} shard(s), any {threshold} reconstruct:")
    for p in written:
        print(f"  {p}")
    if manifest_target is not None:
        print(f"  manifest: {manifest_target}")
    print("\nEach shard is self-contained and reveals NOTHING on its own.")
    print("Store shards in separate places; keep fewer than the threshold in any one place.")


def _cmd_protect(args) -> None:
    secret = _read_input(args.input)
    labels = args.labels.split(",") if args.labels else [f"{i:02d}" for i in range(1, args.shares + 1)]
    _do_protect(
        secret,
        args.threshold,
        args.shares,
        args.out_dir,
        labels,
        "protect",
        force=args.force,
        manifest_path=getattr(args, "manifest", None),
    )


def _cmd_recover(args) -> None:
    shard_b64 = [_read_shard_file(p) for p in args.shards]
    try:
        secret = core.recover(shard_b64)
    except ValueError as exc:
        sys.exit(f"error: {exc}")
    _emit_secret(args, secret)


def _cmd_info(args) -> None:
    try:
        meta = core.parse_shard(_read_shard_file(args.shard))
    except ValueError as exc:
        sys.exit(f"error: {exc}")
    print(
        f"mode=protect version={meta['version']} "
        f"threshold={meta['threshold']} shares={meta['shares']} index={meta['index']} "
        f"ciphertext_bytes={len(meta['ciphertext'])}"
    )


def _format_combinations(values) -> str:
    if not values:
        return "none"
    return ",".join("+".join(str(index) for index in value) for value in values)


def _cmd_verify_set(args) -> None:
    shard_b64 = [_read_shard_file(path) for path in args.shards]
    verification = core.verify_complete_set(shard_b64)
    complete = verification.supplied_indices == tuple(
        range(1, verification.declared_total + 1)
    )
    passed = verification.ok and (complete or not args.require_complete)
    version = core.parse_shard(shard_b64[0])["version"]
    tested = (
        len(verification.successful_combinations)
        + len(verification.failed_combinations)
    )
    print(f"set_id: {verification.set_id}")
    print(f"format: SHRD-v{version}")
    print(f"threshold: {verification.threshold}")
    print(f"declared_total: {verification.declared_total}")
    print(
        "supplied_indices: "
        + ",".join(str(index) for index in verification.supplied_indices)
    )
    print(f"tested_combinations: {tested}")
    print(
        "successful_combinations: "
        f"{_format_combinations(verification.successful_combinations)}"
    )
    print(
        "failed_combinations: "
        f"{_format_combinations(verification.failed_combinations)}"
    )
    print(f"complete_set: {'yes' if complete else 'no'}")
    print(f"result: {'PASS' if passed else 'FAIL'}")
    if not passed:
        raise SystemExit(1)


def _prompt_fordefi_phrase(args) -> bytes:
    if not sys.stdin.isatty():
        raise ValueError("interactive Fordefi phrase entry requires a TTY")
    allow_nonstandard = getattr(args, "allow_nonstandard_phrase", False)
    first = fordefi_support.canonicalize_recovery_phrase(
        getpass.getpass("Fordefi recovery phrase: "),
        allow_nonstandard=allow_nonstandard,
    )
    second = fordefi_support.canonicalize_recovery_phrase(
        getpass.getpass("Confirm Fordefi recovery phrase: "),
        allow_nonstandard=allow_nonstandard,
    )
    if first != second:
        raise ValueError("Fordefi recovery phrase entries do not match")
    return first


def _cmd_fordefi_split(args) -> None:
    if args.phrase_file:
        phrase = fordefi_support.read_recovery_phrase_file(
            args.phrase_file,
            allow_nonstandard=getattr(args, "allow_nonstandard_phrase", False),
            allow_insecure=getattr(args, "allow_insecure_phrase_file", False),
        )
    else:
        phrase = _prompt_fordefi_phrase(args)
    labels = args.labels.split(",") if args.labels else [f"{i:02d}" for i in range(1, args.shares + 1)]
    if args.slip39:
        if getattr(args, "manifest", None):
            raise ValueError("--manifest is available only for SHRD output")
        try:
            mnemonics = slip39.split_bip39(phrase.decode(), args.threshold, args.shares)
        except Exception as exc:
            sys.exit(f"error: {exc}\n(the phrase must be a valid BIP-39 mnemonic for SLIP-39; "
                     f"otherwise omit --slip39 to use AEAD+Shamir shards)")
        _do_slip39_split(
            mnemonics,
            args.out_dir,
            labels,
            "fordefi",
            args.threshold,
            args.shares,
            "bip39",
            force=args.force,
        )
    else:
        _do_protect(
            phrase,
            args.threshold,
            args.shares,
            args.out_dir,
            labels,
            "fordefi",
            force=args.force,
            manifest_path=getattr(args, "manifest", None),
        )
    print("\nGive one share to each holder; store them in separate places.")
    print(f"Any {args.threshold} shares together rebuild the phrase; fewer reveal nothing.")
    print("A holder that only stores a share cannot rebuild anything alone.")
    print("To recover later, run `shard-core fordefi combine ...` offline, then feed the phrase")
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
    _emit_secret(args, phrase)


# --------------------------------------------------------------------------- #
# SLIP-39 (optional; needs the `slip39` extra)
# --------------------------------------------------------------------------- #
def _slip39_passphrase(args) -> bytes:
    if getattr(args, "passphrase_env", None) or getattr(args, "passphrase_file", None):
        return _get_passphrase(args, confirm=False)
    return b""


def _read_mnemonic_file(path: str) -> str:
    lines = Path(path).read_text().splitlines()
    words = " ".join(ln.strip() for ln in lines if ln.strip() and not ln.lstrip().startswith("#"))
    return " ".join(words.split())


def _write_mnemonic_share(path, label, mnemonic, mode, k, n, i, source, *, force) -> str:
    tag = f" [{label}]" if label else ""
    comment = (
        f"# shard-core SLIP-39 {mode}({source}) "
        f"{k}-of-{n} share {i}/{n}{tag}\n"
    )
    _write_text(str(path), comment + mnemonic + "\n", force=force)
    return str(path)


def _do_slip39_split(
    mnemonics,
    out_dir,
    labels,
    mode,
    k,
    n,
    source,
    *,
    force=False,
) -> None:
    labels = core.normalize_labels(labels, n)
    output_dir = safeio.ensure_private_dir(out_dir)
    paths = [
        output_dir / f"share-{label}.txt"
        for label in labels
    ]
    safeio.preflight_output_paths(paths, force=force)
    written = [
        _write_mnemonic_share(
            path,
            label,
            mn,
            mode,
            k,
            n,
            i,
            source,
            force=force,
        )
        for i, (mn, label, path) in enumerate(
            zip(mnemonics, labels, paths),
            start=1,
        )
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
    _do_slip39_split(
        mnemonics,
        args.out_dir,
        labels,
        "slip39",
        args.threshold,
        args.shares,
        source,
        force=args.force,
    )


def _cmd_slip39_combine(args) -> None:
    pw = _slip39_passphrase(args)
    mnemonics = [_read_mnemonic_file(p) for p in args.shares]
    try:
        secret = slip39.combine(mnemonics, pw)
    except Exception as exc:
        sys.exit(f"error: {exc}")
    if args.bip39:
        _emit_secret(args, (slip39.entropy_to_bip39(secret) + "\n").encode())
    elif args.hex:
        _emit_secret(args, (secret.hex() + "\n").encode())
    else:
        _emit_secret(args, secret)


def _cmd_generate_key(args) -> None:
    if not (16 <= args.bytes <= 1024):
        raise ValueError("--bytes must be between 16 and 1024")
    if args.output == "-":
        raise ValueError("generate-key refuses stdout; use --output FILE")

    key = secrets.token_bytes(args.bytes)
    if args.encoding == "hex":
        encoded = key.hex().encode("ascii") + b"\n"
    elif args.encoding == "base64":
        encoded = base64.b64encode(key) + b"\n"
    else:
        encoded = key

    safeio.atomic_write_bytes(
        args.output,
        encoded,
        force=args.force,
    )
    print(
        f"wrote {args.bytes}-byte {args.encoding} credential to {args.output}"
    )


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def _add_passphrase_opts(p: argparse.ArgumentParser) -> None:
    p.add_argument("--passphrase-env", metavar="VAR", help="read passphrase from an env var")
    p.add_argument("--passphrase-file", metavar="FILE", help="read passphrase from a file")
    p.add_argument(
        "--allow-insecure-passphrase-file",
        action="store_true",
        help="allow a symlink or group/world-accessible passphrase file",
    )


def _add_secret_output_args(parser: argparse.ArgumentParser) -> None:
    output = parser.add_mutually_exclusive_group(required=True)
    output.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="write sensitive plaintext to FILE",
    )
    output.add_argument(
        "--stdout",
        action="store_true",
        help="explicitly write sensitive plaintext to stdout",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace an existing regular output file; symlinks are never followed",
    )


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
    enc.add_argument(
        "--force",
        action="store_true",
        help="replace an existing regular output file; symlinks are never followed",
    )
    enc.add_argument("--scrypt-n", type=int, default=core.DEFAULT_SCRYPT_N_LOG2,
                     dest="scrypt_n", metavar="LOG2", help="scrypt cost as log2(N) (default 17)")
    _add_passphrase_opts(enc)
    enc.set_defaults(func=_cmd_encrypt)

    dec = sub.add_parser("decrypt", help="passphrase-decrypt a secret")
    dec.add_argument("-i", "--input", default="-", help="input file, or - for stdin")
    _add_secret_output_args(dec)
    _add_passphrase_opts(dec)
    dec.set_defaults(func=_cmd_decrypt)

    pro = sub.add_parser("protect", help="encrypt + Shamir-split into n-of-m shards")
    pro.add_argument("-t", "--threshold", type=int, required=True, help="shards needed to recover (k)")
    pro.add_argument("-n", "--shares", type=int, required=True, help="total shards (m)")
    pro.add_argument("-i", "--input", default="-", help="secret file, or - for stdin")
    pro.add_argument("-o", "--out-dir", default="shards", dest="out_dir", help="output directory")
    pro.add_argument("--labels", help="comma-separated labels (one per shard)")
    pro.add_argument(
        "--manifest",
        metavar="FILE",
        help="write a non-secret SHRD inventory manifest",
    )
    pro.add_argument(
        "--force",
        action="store_true",
        help="replace existing regular share files; symlinks are never followed",
    )
    pro.set_defaults(func=_cmd_protect)

    rec = sub.add_parser("recover", help="reconstruct a secret from shards")
    _add_secret_output_args(rec)
    rec.add_argument("shards", nargs="+", help="shard files (>= threshold)")
    rec.set_defaults(func=_cmd_recover)

    inf = sub.add_parser("info", help="show a shard's header without reconstructing")
    inf.add_argument("shard", help="a shard file")
    inf.set_defaults(func=_cmd_info)

    verify = sub.add_parser(
        "verify-set",
        help="authenticate every threshold combination in a SHRD set",
    )
    verify.add_argument(
        "--require-complete",
        action="store_true",
        help="also require every declared share index",
    )
    verify.add_argument("shards", nargs="+", help="SHRD share files")
    verify.set_defaults(func=_cmd_verify_set)

    fd = sub.add_parser("fordefi", help="guided Fordefi recovery-phrase workflow")
    fdsub = fd.add_subparsers(dest="fordefi_command", required=True)

    fds = fdsub.add_parser("split", help="shard a Fordefi recovery phrase")
    fds.add_argument("-t", "--threshold", type=int, default=2, help="shards needed (default 2)")
    fds.add_argument("-n", "--shares", type=int, default=3, help="total shards (default 3)")
    fds.add_argument(
        "--phrase-file",
        help="controlled automation file; hidden interactive entry is preferred",
    )
    fds.add_argument(
        "--allow-nonstandard-phrase",
        action="store_true",
        help="allow a non-12-word or non-lowercase ASCII Fordefi phrase",
    )
    fds.add_argument(
        "--allow-insecure-phrase-file",
        action="store_true",
        help="allow a symlink or group/world-accessible phrase file",
    )
    fds.add_argument("--labels", help="comma-separated labels (default: numbered 01..0n)")
    fds.add_argument("-o", "--out-dir", default="fordefi-shards", dest="out_dir", help="output directory")
    fds.add_argument(
        "--manifest",
        metavar="FILE",
        help="write a non-secret SHRD inventory manifest",
    )
    fds.add_argument(
        "--force",
        action="store_true",
        help="replace existing regular share files; symlinks are never followed",
    )
    fds.add_argument("--slip39", action="store_true",
                     help="emit SLIP-39 word-list shares (phrase must be valid BIP-39)")
    fds.set_defaults(func=_cmd_fordefi_split)

    fdc = fdsub.add_parser("combine", help="recover a Fordefi recovery phrase")
    _add_secret_output_args(fdc)
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
    s39s.add_argument(
        "--force",
        action="store_true",
        help="replace existing regular share files; symlinks are never followed",
    )
    _add_passphrase_opts(s39s)
    s39s.set_defaults(func=_cmd_slip39_split)

    s39c = s39sub.add_parser("combine", help="reconstruct a secret from SLIP-39 shares")
    s39c.add_argument("shares", nargs="+", help="SLIP-39 share files (>= threshold)")
    _add_secret_output_args(s39c)
    s39c.add_argument("--bip39", action="store_true", help="output as a BIP-39 phrase")
    s39c.add_argument("--hex", action="store_true", help="output as hex")
    _add_passphrase_opts(s39c)
    s39c.set_defaults(func=_cmd_slip39_combine)

    keygen = sub.add_parser(
        "generate-key",
        help="generate a random wrapping credential into a private file",
    )
    keygen.add_argument(
        "--bytes",
        type=int,
        required=True,
        help="random byte count (16..1024)",
    )
    keygen.add_argument(
        "--encoding",
        choices=("hex", "base64", "raw"),
        required=True,
        help="output encoding",
    )
    keygen.add_argument(
        "-o",
        "--output",
        required=True,
        metavar="FILE",
        help="write the credential to FILE; stdout is refused",
    )
    keygen.add_argument(
        "--force",
        action="store_true",
        help="replace an existing regular output file; symlinks are never followed",
    )
    keygen.set_defaults(func=_cmd_generate_key)

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
    try:
        args.func(args)
    except (OSError, RuntimeError, ValueError) as exc:
        sys.exit(f"error: {exc}")


if __name__ == "__main__":
    main()
