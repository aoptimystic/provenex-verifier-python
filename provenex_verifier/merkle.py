"""RFC 6962 Merkle inclusion-proof verification.

A receipt may carry a ``transparency_log`` block with a ``tree_size`` and a
``tree_root``, plus a per-source ``inclusion_proof``. With those values and
the leaf hash, anyone can verify that the leaf is committed under the
published tree head without rebuilding the tree.

The leaf-hash and node-hash domain separators (``0x00`` and ``0x01``
respectively) come from RFC 6962 section 2.1 and are non-negotiable: omitting
them enables second-preimage attacks.

This module deliberately exposes only the verification side. Tree
construction lives in the producer (provenex-core), not here.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence as _SequenceABC
from typing import Sequence


_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"
_HASH_LEN = 32


def _hash_node(left: bytes, right: bytes) -> bytes:
    """RFC 6962 internal-node hash: ``SHA-256(0x01 || left || right)``."""
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def hash_leaf(leaf: bytes) -> bytes:
    """RFC 6962 leaf hash: ``SHA-256(0x00 || leaf)``.

    Use this to derive ``leaf_hash`` for :func:`verify_inclusion_proof` when
    you have the raw leaf bytes (the canonical receipt payload, for the
    transparency-log use case). Exposed because users who store leaf bytes
    rather than precomputed leaf hashes need a vetted implementation.
    """
    if not isinstance(leaf, (bytes, bytearray)):
        raise TypeError(f"leaf must be bytes, got {type(leaf).__name__}")
    return hashlib.sha256(_LEAF_PREFIX + bytes(leaf)).digest()


def verify_inclusion_proof(
    leaf_hash: bytes,
    proof: Sequence[bytes],
    tree_root: bytes,
    leaf_index: int,
    tree_size: int,
) -> bool:
    """Verify an RFC 6962 inclusion proof.

    Args:
        leaf_hash: The domain-separated leaf hash, i.e.
            ``SHA-256(0x00 || leaf_bytes)``. Must be exactly 32 bytes. If you
            have the raw leaf bytes, derive the hash with :func:`hash_leaf`
            first.
        proof: The audit path from leaf to root. Each element is a 32-byte
            sibling hash.
        tree_root: The published tree head to verify against. 32 bytes.
        leaf_index: 0-based position of the leaf in the log.
        tree_size: Total number of leaves the proof was produced against
            (i.e. the size of the tree whose head is ``tree_root``).

    Returns:
        ``True`` iff the proof verifies ``leaf_hash`` to ``tree_root`` for
        the given index and tree size. ``False`` on any mismatch, including
        malformed inputs (wrong byte lengths, out-of-range index, negative
        size, non-bytes elements).

    The function is total: it does not raise on bad input, it returns
    ``False``. A bad proof and a malformed proof are both verification
    failures from the caller's perspective.
    """
    if not isinstance(tree_size, int) or tree_size <= 0:
        return False
    if not isinstance(leaf_index, int) or leaf_index < 0 or leaf_index >= tree_size:
        return False
    if not isinstance(leaf_hash, (bytes, bytearray)) or len(leaf_hash) != _HASH_LEN:
        return False
    if not isinstance(tree_root, (bytes, bytearray)) or len(tree_root) != _HASH_LEN:
        return False
    if not isinstance(proof, _SequenceABC) or isinstance(proof, (str, bytes, bytearray)):
        return False

    fn = bytes(leaf_hash)
    sn = tree_size - 1
    r = leaf_index

    for sibling in proof:
        if not isinstance(sibling, (bytes, bytearray)) or len(sibling) != _HASH_LEN:
            return False
        sib = bytes(sibling)
        if sn == 0:
            return False
        if (r & 1) == 1 or r == sn:
            fn = _hash_node(sib, fn)
            while (r & 1) == 0 and r != 0:
                r >>= 1
                sn >>= 1
        else:
            fn = _hash_node(fn, sib)
        r >>= 1
        sn >>= 1

    return fn == bytes(tree_root) and sn == 0
