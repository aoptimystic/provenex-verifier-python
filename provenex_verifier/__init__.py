"""Standalone verifier for Provenex receipts.

Public API:

    verify_receipt(receipt, public_key) -> VerificationResult
        Verify the Ed25519 signature on a receipt.

    canonicalize(receipt) -> bytes
        Produce the canonical signed-payload bytes for a receipt.

    verify_inclusion_proof(leaf_hash, proof, tree_root, leaf_index, tree_size) -> bool
        Verify an RFC 6962 Merkle inclusion proof.

    VerificationResult
        NamedTuple returned by verify_receipt.

The library has a single runtime dependency (``cryptography``) and makes no
network calls. It is safe to run in an air-gapped environment.
"""

from .canonical import canonicalize
from .merkle import verify_inclusion_proof
from .verifier import VerificationResult, verify_receipt

__version__ = "1.0.0"

__all__ = [
    "VerificationResult",
    "__version__",
    "canonicalize",
    "verify_inclusion_proof",
    "verify_receipt",
]
