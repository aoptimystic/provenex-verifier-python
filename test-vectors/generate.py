"""Regenerate the static test vectors in this directory.

Run from the repo root::

    python test-vectors/generate.py

Produces:

* ``ed25519_public_key.pem``           -- public key for verification
* ``valid_minimal_receipt.json``       -- minimal signed receipt
* ``valid_full_receipt.json``          -- richer signed receipt with optional fields
* ``tampered_field_receipt.json``      -- valid_full with one field mutated post-sign
* ``hmac_receipt.json``                -- HMAC-signed receipt (must be rejected by the verifier)

The private key is *not* persisted: vectors are checked in along with the
public key only. Regenerating overwrites all five files with a fresh keypair.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


HERE = Path(__file__).resolve().parent


def canonicalize(receipt: dict) -> bytes:
    """Mirror of provenex_verifier.canonical.canonicalize."""
    payload = {k: v for k, v in receipt.items() if k != "signature"}
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sign(receipt: dict, priv: Ed25519PrivateKey) -> dict:
    out = dict(receipt)
    out.pop("signature", None)
    sig = priv.sign(canonicalize(out)).hex()
    out["signature"] = {"algorithm": "ed25519", "value": sig}
    return out


MINIMAL = {
    "receipt_id": "prx_00000000000000000000000000000001",
    "schema_version": "2.5.0",
    "issued_at": "2026-05-25T12:00:00.000Z",
    "issuer": "provenex-core/1.0.0",
    "output": {
        "hash": "sha256:" + "0" * 64,
        "hash_algorithm": "sha256",
    },
    "sources": [],
    "policy": {
        "verification": {
            "block_stale": False,
            "block_unauthorized": True,
            "block_unverified": False,
            "block_tampered": True,
            "flag_stale": True,
            "flag_unauthorized": True,
            "flag_unverified": True,
            "flag_tampered": True,
        }
    },
    "summary": {
        "total_chunks": 0,
        "verified": 0,
        "stale": 0,
        "unauthorized": 0,
        "unverified": 0,
        "tampered": 0,
        "overall_status": "PASS",
    },
}


FULL = {
    "receipt_id": "prx_00000000000000000000000000000002",
    "schema_version": "2.5.0",
    "issued_at": "2026-05-25T12:00:00.123Z",
    "issuer": "provenex-core/1.0.0",
    "caller_hash": "sha256:" + "a" * 64,
    "output": {
        "hash": "sha256:" + "1" * 64,
        "hash_algorithm": "sha256",
    },
    "sources": [
        {
            "chunk_index": 0,
            "fingerprint": "sha256:" + "b" * 64,
            "document_id": "doc_policy_v4",
            "document_version": "sha256:" + "c" * 64,
            "ingested_at": "2026-04-01T09:00:00.000Z",
            "chunk_offset": 0,
            "chunk_length": 512,
            "authorized": True,
            "verification_outcome": "VERIFIED",
            "normalization_applied": ["unicode_nfc", "whitespace_collapse"],
            "entry_kind": "whole_chunk",
            "claims": {"classification": "public", "jurisdiction": "EU"},
        },
        {
            "chunk_index": 1,
            "fingerprint": "sha256:" + "d" * 64,
            "verification_outcome": "UNVERIFIED",
            "entry_kind": "whole_chunk",
            "authorized": False,
        },
    ],
    "policy": {
        "verification": {
            "block_stale": False,
            "block_unauthorized": True,
            "block_unverified": False,
            "block_tampered": True,
            "flag_stale": True,
            "flag_unauthorized": True,
            "flag_unverified": True,
            "flag_tampered": True,
        },
        "access_control": {
            "rules_fired": [],
            "decisions": [{"chunk_index": 0, "decision": "allow"}],
        },
    },
    "summary": {
        "total_chunks": 2,
        "verified": 1,
        "stale": 0,
        "unauthorized": 0,
        "unverified": 1,
        "tampered": 0,
        "overall_status": "PASS",
    },
    "transparency_log": {
        "tree_size": 42,
        "tree_root": "sha256:" + "e" * 64,
    },
}


HMAC_RECEIPT = {
    "receipt_id": "prx_00000000000000000000000000000003",
    "schema_version": "2.5.0",
    "issued_at": "2026-05-25T12:00:00.000Z",
    "issuer": "provenex-core/1.0.0",
    "output": {
        "hash": "sha256:" + "2" * 64,
        "hash_algorithm": "sha256",
    },
    "sources": [],
    "policy": {
        "verification": {
            "block_stale": False,
            "block_unauthorized": True,
            "block_unverified": False,
            "block_tampered": True,
            "flag_stale": True,
            "flag_unauthorized": True,
            "flag_unverified": True,
            "flag_tampered": True,
        }
    },
    "summary": {
        "total_chunks": 0,
        "verified": 0,
        "stale": 0,
        "unauthorized": 0,
        "unverified": 0,
        "tampered": 0,
        "overall_status": "PASS",
    },
}


def main() -> None:
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    (HERE / "ed25519_public_key.pem").write_bytes(pub_pem)

    minimal = sign(MINIMAL, priv)
    (HERE / "valid_minimal_receipt.json").write_text(
        json.dumps(minimal, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    full = sign(FULL, priv)
    (HERE / "valid_full_receipt.json").write_text(
        json.dumps(full, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    tampered = json.loads(json.dumps(full))
    tampered["summary"]["overall_status"] = "BLOCK"
    (HERE / "tampered_field_receipt.json").write_text(
        json.dumps(tampered, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    hmac_secret = b"shared-secret-for-hmac-test-vector"
    hmac_body = dict(HMAC_RECEIPT)
    hmac_body.pop("signature", None)
    hmac_sig = hmac.new(
        hmac_secret, canonicalize(hmac_body), hashlib.sha256
    ).hexdigest()
    hmac_body["signature"] = {"algorithm": "hmac-sha256", "value": hmac_sig}
    (HERE / "hmac_receipt.json").write_text(
        json.dumps(hmac_body, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    print(f"wrote vectors to {HERE}")


if __name__ == "__main__":
    main()
