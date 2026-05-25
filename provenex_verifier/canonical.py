"""Canonical JSON serialization for Provenex receipts.

The canonical form is what gets signed. Any verifier that wants to reproduce
the signed bytes must follow the same rules. The serialization is exposed
publicly so callers can audit the canonicalization step independently of
signature verification.

Rules:

* The ``signature`` block is stripped before serialization. Signing a receipt
  is signing every byte of its canonical form *except* the signature itself.
* Keys are sorted lexicographically at every level of nesting.
* Separators are ``","`` and ``":"`` (no whitespace).
* Non-ASCII characters (smart quotes, accented letters, CJK) are emitted as
  raw UTF-8, not as ``\\uXXXX`` escapes. This matches the producer side and
  keeps the form portable to non-Python verifiers.
* ``NaN``, ``Infinity``, and ``-Infinity`` are rejected.

Matches provenex-core ``ProvenanceReceipt.canonical_payload`` as of receipt
schema 2.5.0.
"""

from __future__ import annotations

import json
from typing import Any, Mapping


def canonicalize(receipt: Mapping[str, Any]) -> bytes:
    """Return the canonical signed-payload bytes for a receipt.

    Args:
        receipt: The receipt dict (typically the output of ``json.loads`` on a
            receipt JSON file). The input is not mutated.

    Returns:
        UTF-8 encoded canonical JSON bytes, with any ``signature`` block
        omitted.

    Raises:
        TypeError: If ``receipt`` is not a mapping, or contains values JSON
            cannot serialize.
        ValueError: If the receipt contains ``NaN``, ``Infinity``, or
            ``-Infinity``.
    """
    if not isinstance(receipt, Mapping):
        raise TypeError(
            f"receipt must be a mapping (dict), got {type(receipt).__name__}"
        )
    payload = {k: v for k, v in receipt.items() if k != "signature"}
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
