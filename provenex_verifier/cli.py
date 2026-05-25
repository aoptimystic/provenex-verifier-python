"""``provenex-verify`` command-line entry point.

Usage::

    provenex-verify <receipt.json> --public-key <key.pem>
    cat receipt.json | provenex-verify - --public-key key.pem

Exit codes:

* ``0`` -- signature verified.
* ``1`` -- signature did not verify (tampered receipt, wrong key, etc.).
* ``2`` -- usage error (missing file, malformed JSON, bad arguments).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional, TextIO

from . import __version__
from .verifier import verify_receipt


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="provenex-verify",
        description=(
            "Verify the Ed25519 signature on a Provenex receipt. "
            "Reads receipt JSON from a file (or '-' for stdin) and an "
            "Ed25519 public key (PEM or DER) from disk."
        ),
    )
    parser.add_argument(
        "receipt",
        help="Path to receipt JSON file, or '-' to read from stdin.",
    )
    parser.add_argument(
        "--public-key",
        required=True,
        help="Path to Ed25519 public key (PEM SubjectPublicKeyInfo or DER).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-field output; rely on exit code only.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"provenex-verify {__version__}",
    )
    return parser


def main(
    argv: Optional[List[str]] = None,
    stdin: Optional[TextIO] = None,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
) -> int:
    """Entry point. Returns an exit code; never raises on normal failures."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr

    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.receipt == "-":
            receipt = json.load(stdin)
        else:
            with open(args.receipt, "r", encoding="utf-8") as fh:
                receipt = json.load(fh)
    except OSError as exc:
        print(f"error: could not read receipt: {exc}", file=stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"error: receipt is not valid JSON: {exc}", file=stderr)
        return 2

    try:
        with open(args.public_key, "rb") as fh:
            key_bytes = fh.read()
    except OSError as exc:
        print(f"error: could not read public key: {exc}", file=stderr)
        return 2

    result = verify_receipt(receipt, key_bytes)

    if not args.quiet:
        print(f"valid:     {result.valid}", file=stdout)
        print(f"signer:    {result.signer or '(missing)'}", file=stdout)
        print(
            f"signed_at: {result.signed_at.isoformat() if result.signed_at else '(unknown)'}",
            file=stdout,
        )
        for err in result.errors:
            print(f"error:     {err}", file=stderr)
        for warn in result.warnings:
            print(f"warning:   {warn}", file=stderr)

    return 0 if result.valid else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
