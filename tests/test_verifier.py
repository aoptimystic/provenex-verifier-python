"""verify_receipt tests, including the spec-required negative cases."""

from __future__ import annotations

import copy
import json
from datetime import datetime, timezone

import pytest

from provenex_verifier import VerificationResult, verify_receipt
from provenex_verifier.verifier import _load_public_key


# ---------------------------------------------------------------- happy paths


def test_valid_signature_with_pem_key(signed_receipt, public_key_pem):
    result = verify_receipt(signed_receipt, public_key_pem)
    assert result.valid is True
    assert result.errors == []
    assert result.signer == "provenex-core/1.0.0"
    assert isinstance(result.signed_at, datetime)
    assert result.signed_at.tzinfo is not None


def test_valid_signature_with_raw_key(signed_receipt, public_key_raw):
    result = verify_receipt(signed_receipt, public_key_raw)
    assert result.valid is True


def test_valid_signature_with_der_key(signed_receipt, public_key_der):
    result = verify_receipt(signed_receipt, public_key_der)
    assert result.valid is True


def test_valid_signature_with_bytearray_key(signed_receipt, public_key_pem):
    result = verify_receipt(signed_receipt, bytearray(public_key_pem))
    assert result.valid is True


def test_result_is_named_tuple(signed_receipt, public_key_pem):
    result = verify_receipt(signed_receipt, public_key_pem)
    assert isinstance(result, VerificationResult)
    assert result._fields == ("valid", "signer", "signed_at", "errors", "warnings")


def test_signed_at_parses_z_suffix(signed_receipt, public_key_pem):
    result = verify_receipt(signed_receipt, public_key_pem)
    assert result.signed_at == datetime(
        2026, 5, 25, 10, 0, 0, tzinfo=timezone.utc
    )


# ---------------------------------------------------------------- spec negative cases


def test_tampered_signature_rejected(signed_receipt, public_key_pem):
    """Flip one bit in the signature value."""
    tampered = copy.deepcopy(signed_receipt)
    sig_hex = tampered["signature"]["value"]
    flipped_byte = (int(sig_hex[:2], 16) ^ 0x01)
    tampered["signature"]["value"] = f"{flipped_byte:02x}" + sig_hex[2:]
    result = verify_receipt(tampered, public_key_pem)
    assert result.valid is False
    assert any("tampered" in e or "signature does not match" in e for e in result.errors)


def test_tampered_field_rejected(signed_receipt, public_key_pem):
    """Modify a field after signing; signature must no longer verify."""
    tampered = copy.deepcopy(signed_receipt)
    tampered["summary"]["overall_status"] = "BLOCK"
    result = verify_receipt(tampered, public_key_pem)
    assert result.valid is False


def test_added_field_rejected(signed_receipt, public_key_pem):
    """Adding a new top-level field after signing also breaks verification."""
    tampered = copy.deepcopy(signed_receipt)
    tampered["extra_field"] = "injected"
    result = verify_receipt(tampered, public_key_pem)
    assert result.valid is False


def test_removed_field_rejected(signed_receipt, public_key_pem):
    """Removing a top-level field after signing breaks verification too."""
    tampered = copy.deepcopy(signed_receipt)
    tampered.pop("issuer", None)
    result = verify_receipt(tampered, public_key_pem)
    assert result.valid is False


def test_wrong_public_key_rejected(signed_receipt):
    """A valid PEM but for a different keypair must fail."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    other = Ed25519PrivateKey.generate()
    other_pem = other.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    result = verify_receipt(signed_receipt, other_pem)
    assert result.valid is False


def test_malformed_canonicalization_rejected(signed_receipt, public_key_pem):
    """A value the canonical encoder can't serialize (NaN) yields a clean failure."""
    broken = copy.deepcopy(signed_receipt)
    broken["weird"] = float("nan")
    result = verify_receipt(broken, public_key_pem)
    assert result.valid is False
    assert any("canonicalization" in e for e in result.errors)


# ---------------------------------------------------------------- input shape errors


def test_non_dict_receipt_rejected(public_key_pem):
    result = verify_receipt(["not", "a", "dict"], public_key_pem)  # type: ignore[arg-type]
    assert result.valid is False
    assert any("mapping" in e for e in result.errors)
    assert result.signer == ""
    assert result.signed_at is None


def test_receipt_without_signature_block_rejected(base_receipt, public_key_pem):
    result = verify_receipt(base_receipt, public_key_pem)
    assert result.valid is False
    assert any("no signature block" in e for e in result.errors)


def test_signature_block_not_dict_rejected(public_key_pem):
    bad = {"issuer": "x", "signature": "not-a-dict"}
    result = verify_receipt(bad, public_key_pem)
    assert result.valid is False
    assert any("no signature block" in e for e in result.errors)


def test_hmac_algorithm_rejected(public_key_pem):
    bad = {
        "issuer": "x",
        "signature": {"algorithm": "hmac-sha256", "value": "ab" * 32},
    }
    result = verify_receipt(bad, public_key_pem)
    assert result.valid is False
    assert any("unsupported signature algorithm" in e for e in result.errors)
    assert "hmac-sha256" in result.errors[0]


def test_unknown_algorithm_rejected(public_key_pem):
    bad = {"signature": {"algorithm": "rsa-pkcs1", "value": "ab" * 64}}
    result = verify_receipt(bad, public_key_pem)
    assert result.valid is False
    assert any("unsupported signature algorithm" in e for e in result.errors)


def test_signature_value_missing_rejected(public_key_pem):
    bad = {"signature": {"algorithm": "ed25519"}}
    result = verify_receipt(bad, public_key_pem)
    assert result.valid is False
    assert any("signature.value" in e for e in result.errors)


def test_signature_value_empty_rejected(public_key_pem):
    bad = {"signature": {"algorithm": "ed25519", "value": ""}}
    result = verify_receipt(bad, public_key_pem)
    assert result.valid is False
    assert any("signature.value" in e for e in result.errors)


def test_signature_value_not_string_rejected(public_key_pem):
    bad = {"signature": {"algorithm": "ed25519", "value": 12345}}
    result = verify_receipt(bad, public_key_pem)
    assert result.valid is False


def test_signature_value_not_hex_rejected(public_key_pem):
    bad = {"signature": {"algorithm": "ed25519", "value": "not-hex-data-zz"}}
    result = verify_receipt(bad, public_key_pem)
    assert result.valid is False
    assert any("not valid hex" in e for e in result.errors)


def test_signature_value_wrong_length_rejected(public_key_pem):
    bad = {"signature": {"algorithm": "ed25519", "value": "ab" * 30}}
    result = verify_receipt(bad, public_key_pem)
    assert result.valid is False
    assert any("64 bytes" in e for e in result.errors)


# ---------------------------------------------------------------- public-key errors


def test_public_key_wrong_type_rejected(signed_receipt):
    result = verify_receipt(signed_receipt, "not-bytes")  # type: ignore[arg-type]
    assert result.valid is False
    assert any("public key" in e for e in result.errors)


def test_public_key_garbage_bytes_rejected(signed_receipt):
    result = verify_receipt(signed_receipt, b"random garbage that is neither pem nor der")
    assert result.valid is False
    assert any("public key" in e for e in result.errors)


def test_public_key_pem_wrong_algorithm_rejected(signed_receipt):
    """A valid RSA PEM is not Ed25519 and must be rejected."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pem = rsa_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    result = verify_receipt(signed_receipt, rsa_pem)
    assert result.valid is False
    assert any("not an Ed25519" in e or "public key error" in e for e in result.errors)


def test_public_key_der_wrong_algorithm_rejected(signed_receipt):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_der = rsa_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    result = verify_receipt(signed_receipt, rsa_der)
    assert result.valid is False


def test_load_public_key_type_error_directly():
    with pytest.raises(TypeError):
        _load_public_key(12345)  # type: ignore[arg-type]


def test_load_public_key_value_error_on_invalid_pem():
    with pytest.raises(ValueError):
        _load_public_key(b"-----BEGIN PUBLIC KEY-----\ngarbage\n-----END PUBLIC KEY-----\n")


# ---------------------------------------------------------------- warnings


def test_missing_optional_fields_emit_warnings(sign_receipt, public_key_pem):
    receipt = sign_receipt({})  # everything optional
    result = verify_receipt(receipt, public_key_pem)
    assert result.valid is True
    assert any("issued_at" in w for w in result.warnings)
    assert any("schema_version" in w for w in result.warnings)
    assert any("receipt_id" in w for w in result.warnings)
    assert any("issuer" in w for w in result.warnings)


def test_malformed_issued_at_warns(base_receipt, sign_receipt, public_key_pem):
    base_receipt["issued_at"] = "not-a-date"
    receipt = sign_receipt(base_receipt)
    result = verify_receipt(receipt, public_key_pem)
    assert result.valid is True
    assert any("issued_at" in w for w in result.warnings)
    assert result.signed_at is None


def test_non_string_issued_at_warns(base_receipt, sign_receipt, public_key_pem):
    base_receipt["issued_at"] = 1234567890
    receipt = sign_receipt(base_receipt)
    result = verify_receipt(receipt, public_key_pem)
    assert result.valid is True
    assert result.signed_at is None


# ---------------------------------------------------------------- static vectors


def test_static_valid_minimal_vector(vectors_dir, load_vector):
    pem = (vectors_dir / "ed25519_public_key.pem").read_bytes()
    result = verify_receipt(load_vector("valid_minimal_receipt.json"), pem)
    assert result.valid, result.errors


def test_static_valid_full_vector(vectors_dir, load_vector):
    pem = (vectors_dir / "ed25519_public_key.pem").read_bytes()
    result = verify_receipt(load_vector("valid_full_receipt.json"), pem)
    assert result.valid, result.errors


def test_static_tampered_field_vector_rejected(vectors_dir, load_vector):
    pem = (vectors_dir / "ed25519_public_key.pem").read_bytes()
    result = verify_receipt(load_vector("tampered_field_receipt.json"), pem)
    assert result.valid is False


def test_static_hmac_vector_rejected(vectors_dir, load_vector):
    pem = (vectors_dir / "ed25519_public_key.pem").read_bytes()
    result = verify_receipt(load_vector("hmac_receipt.json"), pem)
    assert result.valid is False
    assert any("unsupported" in e for e in result.errors)


# ---------------------------------------------------------------- end-to-end JSON


def test_round_trip_via_json_serialization(signed_receipt, public_key_pem):
    blob = json.dumps(signed_receipt)
    parsed = json.loads(blob)
    result = verify_receipt(parsed, public_key_pem)
    assert result.valid


def test_unicode_payload_round_trips(base_receipt, sign_receipt, public_key_pem):
    base_receipt["issuer"] = "provenex-core/1.0.0 “smart-quotes” café 中文"
    receipt = sign_receipt(base_receipt)
    # Serialize and reparse to confirm the canonical bytes survive a JSON round-trip.
    receipt = json.loads(json.dumps(receipt, ensure_ascii=False))
    result = verify_receipt(receipt, public_key_pem)
    assert result.valid, result.errors
