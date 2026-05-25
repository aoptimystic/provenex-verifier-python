"""Receipt signature verification.

The verifier confirms a single property: the receipt's Ed25519 signature is
valid over the canonical payload under the supplied public key. It does not
interpret outcomes, walk policy rules, follow trajectory links, or check
Merkle inclusion. Those checks live in callers and in :mod:`.merkle`.

The verifier supports Ed25519 only. HMAC-SHA256 is a symmetric algorithm
useful inside the issuing organization but not for third-party verification:
anyone who can verify an HMAC can also forge one. A standalone verifier is by
definition third-party, so HMAC receipts are explicitly rejected with a
clear error rather than quietly accepted.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, List, Mapping, NamedTuple, Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonicalize


_ED25519_ALG = "ed25519"
_ED25519_SIG_LEN = 64
_ED25519_RAW_KEY_LEN = 32


class VerificationResult(NamedTuple):
    """Outcome of a receipt verification.

    Attributes:
        valid: ``True`` iff the signature verified successfully and no fatal
            errors were encountered. ``False`` on any cryptographic failure
            or malformed input.
        signer: The receipt's ``issuer`` field, if present (e.g.
            ``"provenex-core/0.10.1"``). Empty string when missing. The
            issuer is *not* cryptographically bound to the verifying key:
            anyone with the private key can claim any issuer string. Treat
            this as informational, not as a trust anchor.
        signed_at: The receipt's ``issued_at`` field parsed as a timezone
            aware :class:`datetime`, or ``None`` if missing/malformed.
        errors: Fatal verification problems (empty when ``valid`` is True).
        warnings: Non-fatal observations (e.g. missing optional fields).
    """

    valid: bool
    signer: str
    signed_at: Optional[datetime]
    errors: List[str]
    warnings: List[str]


def _parse_iso8601(value: Any) -> Optional[datetime]:
    """Parse the receipt's ``issued_at`` (ISO-8601, ``Z`` suffix) defensively."""
    if not isinstance(value, str) or not value:
        return None
    candidate = value
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        return None


def _load_public_key(public_key: Union[bytes, bytearray]) -> Ed25519PublicKey:
    """Accept PEM, DER (SubjectPublicKeyInfo), or 32-byte raw Ed25519 public key.

    Raises:
        TypeError: If ``public_key`` is not bytes-like.
        ValueError: If the bytes do not decode to an Ed25519 public key in
            any supported format.
    """
    if not isinstance(public_key, (bytes, bytearray)):
        raise TypeError(
            f"public_key must be bytes, got {type(public_key).__name__}"
        )
    key_bytes = bytes(public_key)

    if b"-----BEGIN" in key_bytes:
        loaded = serialization.load_pem_public_key(key_bytes)
        if not isinstance(loaded, Ed25519PublicKey):
            raise ValueError(
                f"PEM is not an Ed25519 public key (got {type(loaded).__name__})"
            )
        return loaded

    if len(key_bytes) == _ED25519_RAW_KEY_LEN:
        return Ed25519PublicKey.from_public_bytes(key_bytes)

    try:
        loaded = serialization.load_der_public_key(key_bytes)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"unrecognized public key format: {exc}") from exc
    if not isinstance(loaded, Ed25519PublicKey):
        raise ValueError(
            f"DER is not an Ed25519 public key (got {type(loaded).__name__})"
        )
    return loaded


def _fail(
    errors: List[str],
    warnings: List[str],
    signer: str,
    signed_at: Optional[datetime],
    message: str,
) -> VerificationResult:
    errors.append(message)
    return VerificationResult(False, signer, signed_at, errors, warnings)


def verify_receipt(
    receipt: Mapping[str, Any],
    public_key: Union[bytes, bytearray],
) -> VerificationResult:
    """Verify the Ed25519 signature on a Provenex receipt.

    Args:
        receipt: The receipt dict, typically produced by ``json.loads`` on a
            receipt JSON file. Not mutated.
        public_key: The Ed25519 public key to verify against. Accepts PEM
            (``-----BEGIN PUBLIC KEY-----`` SubjectPublicKeyInfo), DER
            (SubjectPublicKeyInfo), or 32-byte raw form.

    Returns:
        A :class:`VerificationResult`. ``valid`` is ``True`` iff the
        signature verified.

    The function never raises on bad input; failures are reported via
    ``valid=False`` and ``errors``. This makes the verifier safe to call on
    untrusted receipts.
    """
    errors: List[str] = []
    warnings: List[str] = []

    if not isinstance(receipt, Mapping):
        return VerificationResult(
            False,
            "",
            None,
            [f"receipt must be a mapping (dict), got {type(receipt).__name__}"],
            warnings,
        )

    issuer = receipt.get("issuer")
    signer_id = issuer if isinstance(issuer, str) else ""
    signed_at = _parse_iso8601(receipt.get("issued_at"))

    sig_block = receipt.get("signature")
    if not isinstance(sig_block, Mapping):
        return _fail(
            errors,
            warnings,
            signer_id,
            signed_at,
            "receipt has no signature block",
        )

    alg = sig_block.get("algorithm")
    if alg != _ED25519_ALG:
        return _fail(
            errors,
            warnings,
            signer_id,
            signed_at,
            f"unsupported signature algorithm: {alg!r} "
            f"(this verifier supports only {_ED25519_ALG!r})",
        )

    sig_value = sig_block.get("value")
    if not isinstance(sig_value, str) or not sig_value:
        return _fail(
            errors,
            warnings,
            signer_id,
            signed_at,
            "signature.value is missing or not a non-empty string",
        )

    try:
        sig_bytes = bytes.fromhex(sig_value)
    except ValueError:
        return _fail(
            errors,
            warnings,
            signer_id,
            signed_at,
            "signature.value is not valid hex",
        )
    if len(sig_bytes) != _ED25519_SIG_LEN:
        return _fail(
            errors,
            warnings,
            signer_id,
            signed_at,
            f"ed25519 signature must be {_ED25519_SIG_LEN} bytes, got {len(sig_bytes)}",
        )

    try:
        key = _load_public_key(public_key)
    except (TypeError, ValueError) as exc:
        return _fail(errors, warnings, signer_id, signed_at, f"public key error: {exc}")

    try:
        payload = canonicalize(receipt)
    except (TypeError, ValueError) as exc:
        return _fail(
            errors,
            warnings,
            signer_id,
            signed_at,
            f"canonicalization failed: {exc}",
        )

    try:
        key.verify(sig_bytes, payload)
    except InvalidSignature:
        return _fail(
            errors,
            warnings,
            signer_id,
            signed_at,
            "signature does not match payload (tampered receipt or wrong public key)",
        )

    if signed_at is None:
        warnings.append("receipt issued_at is missing or not ISO-8601")
    if not isinstance(receipt.get("schema_version"), str):
        warnings.append("receipt schema_version is missing or not a string")
    if not isinstance(receipt.get("receipt_id"), str):
        warnings.append("receipt receipt_id is missing or not a string")
    if not signer_id:
        warnings.append("receipt issuer is missing or not a string")

    return VerificationResult(True, signer_id, signed_at, errors, warnings)
