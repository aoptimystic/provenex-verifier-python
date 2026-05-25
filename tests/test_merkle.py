"""RFC 6962 inclusion-proof tests."""

from __future__ import annotations

import hashlib
from typing import List, Sequence, Tuple

import pytest

from provenex_verifier import verify_inclusion_proof
from provenex_verifier.merkle import hash_leaf


def _h_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_pow2_lt(n: int) -> int:
    """Largest power of two strictly less than n. Defined for n >= 2."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _mth(leaves: Sequence[bytes]) -> bytes:
    """Merkle Tree Hash per RFC 6962 §2.1."""
    n = len(leaves)
    if n == 1:
        return hash_leaf(leaves[0])
    k = _largest_pow2_lt(n)
    return _h_node(_mth(leaves[:k]), _mth(leaves[k:]))


def _path(m: int, leaves: Sequence[bytes]) -> List[bytes]:
    """RFC 6962 audit path for leaf index ``m`` in tree ``leaves``."""
    n = len(leaves)
    if n == 1:
        return []
    k = _largest_pow2_lt(n)
    if m < k:
        return _path(m, leaves[:k]) + [_mth(leaves[k:])]
    return _path(m - k, leaves[k:]) + [_mth(leaves[:k])]


def _inclusion_proof(
    leaves: Sequence[bytes], index: int
) -> Tuple[bytes, List[bytes], bytes, int, int]:
    """Compute an RFC 6962 inclusion proof for ``leaves[index]``."""
    return (
        hash_leaf(leaves[index]),
        _path(index, leaves),
        _mth(leaves),
        index,
        len(leaves),
    )


# ---------------------------------------------------------------- positive cases


@pytest.mark.parametrize("size", [1, 2, 3, 4, 5, 7, 8, 16, 17, 31, 32])
def test_proof_verifies_for_every_leaf(size: int):
    leaves = [f"leaf-{i}".encode() for i in range(size)]
    for i in range(size):
        leaf_hash, proof, root, idx, n = _inclusion_proof(leaves, i)
        assert verify_inclusion_proof(leaf_hash, proof, root, idx, n)


def test_single_leaf_empty_proof():
    leaf = b"only"
    lh = hash_leaf(leaf)
    assert verify_inclusion_proof(lh, [], lh, 0, 1)


def test_hash_leaf_matches_rfc6962():
    expected = hashlib.sha256(b"\x00hello").digest()
    assert hash_leaf(b"hello") == expected


def test_hash_leaf_type_error_on_str():
    with pytest.raises(TypeError):
        hash_leaf("not-bytes")  # type: ignore[arg-type]


# ---------------------------------------------------------------- negative cases


def test_wrong_root_fails():
    leaves = [b"a", b"b", b"c", b"d"]
    leaf_hash, proof, root, idx, n = _inclusion_proof(leaves, 1)
    bad_root = bytes(32)
    assert not verify_inclusion_proof(leaf_hash, proof, bad_root, idx, n)


def test_tampered_proof_element_fails():
    leaves = [b"a", b"b", b"c", b"d"]
    leaf_hash, proof, root, idx, n = _inclusion_proof(leaves, 1)
    tampered = list(proof)
    tampered[0] = bytes([(tampered[0][0] ^ 0xFF)]) + tampered[0][1:]
    assert not verify_inclusion_proof(leaf_hash, tampered, root, idx, n)


def test_wrong_index_fails():
    leaves = [b"a", b"b", b"c", b"d"]
    leaf_hash, proof, root, _, n = _inclusion_proof(leaves, 1)
    assert not verify_inclusion_proof(leaf_hash, proof, root, 2, n)


def test_wrong_tree_size_fails():
    leaves = [b"a", b"b", b"c", b"d"]
    leaf_hash, proof, root, idx, _ = _inclusion_proof(leaves, 1)
    assert not verify_inclusion_proof(leaf_hash, proof, root, idx, 8)


def test_zero_tree_size_fails():
    assert not verify_inclusion_proof(b"\x00" * 32, [], b"\x00" * 32, 0, 0)


def test_negative_tree_size_fails():
    assert not verify_inclusion_proof(b"\x00" * 32, [], b"\x00" * 32, 0, -1)


def test_non_int_tree_size_fails():
    assert not verify_inclusion_proof(b"\x00" * 32, [], b"\x00" * 32, 0, "two")  # type: ignore[arg-type]


def test_negative_leaf_index_fails():
    assert not verify_inclusion_proof(b"\x00" * 32, [], b"\x00" * 32, -1, 1)


def test_index_out_of_range_fails():
    assert not verify_inclusion_proof(b"\x00" * 32, [], b"\x00" * 32, 1, 1)


def test_non_int_leaf_index_fails():
    assert not verify_inclusion_proof(b"\x00" * 32, [], b"\x00" * 32, "zero", 1)  # type: ignore[arg-type]


def test_short_leaf_hash_fails():
    assert not verify_inclusion_proof(b"\x00" * 31, [], b"\x00" * 32, 0, 1)


def test_short_root_fails():
    assert not verify_inclusion_proof(b"\x00" * 32, [], b"\x00" * 31, 0, 1)


def test_non_bytes_leaf_hash_fails():
    assert not verify_inclusion_proof("not-bytes", [], b"\x00" * 32, 0, 1)  # type: ignore[arg-type]


def test_non_bytes_root_fails():
    assert not verify_inclusion_proof(b"\x00" * 32, [], "not-bytes", 0, 1)  # type: ignore[arg-type]


def test_non_bytes_proof_element_fails():
    leaves = [b"a", b"b"]
    leaf_hash, proof, root, idx, n = _inclusion_proof(leaves, 0)
    assert not verify_inclusion_proof(leaf_hash, ["not-bytes"], root, idx, n)  # type: ignore[list-item]


def test_short_proof_element_fails():
    leaves = [b"a", b"b"]
    leaf_hash, _, root, idx, n = _inclusion_proof(leaves, 0)
    assert not verify_inclusion_proof(leaf_hash, [b"\x00" * 31], root, idx, n)


def test_extra_proof_elements_fail():
    leaves = [b"a", b"b"]
    leaf_hash, proof, root, idx, n = _inclusion_proof(leaves, 0)
    too_many = list(proof) + [b"\x00" * 32]
    assert not verify_inclusion_proof(leaf_hash, too_many, root, idx, n)


# ---------------------------------------------------------------- core compatibility


def test_proof_from_provenex_core_verifies():
    """Frozen proof generated by provenex-core's MerkleTree.

    Regression check that this verifier accepts byte-for-byte what core emits.
    To regenerate (when core's tree format changes intentionally), run::

        from provenex.core.merkle import MerkleTree
        t = MerkleTree()
        for i in range(5):
            t.append(f"leaf-{i}".encode())
        print(t.root().hex(), [h.hex() for h in t.inclusion_proof(2)])
    """
    leaves = [f"leaf-{i}".encode() for i in range(5)]
    expected_root = bytes.fromhex(
        "00d21829a5503145348abcf712513eacf2a274211ad83e970202bb5b6d80b286"
    )
    expected_proof = [
        bytes.fromhex(
            "f76836325aec5699d8d71f8e42e9d47c5c29b08059ba296384f7ca40ad3a40ae"
        ),
        bytes.fromhex(
            "60a53eed0de87a90c8e59427c59c46253c33a76a09502a51801300927b7e6bdc"
        ),
        bytes.fromhex(
            "ea9fc1a1b6e191b460d0d6306e3e870c173f39330f13cda1b70cfc72bdc398ba"
        ),
    ]
    leaf_hash = hash_leaf(leaves[2])
    assert verify_inclusion_proof(leaf_hash, expected_proof, expected_root, 2, 5)


def test_none_proof_returns_false():
    """Regression: a None proof must not raise; the function is total."""
    leaf_hash = hash_leaf(b"x")
    assert not verify_inclusion_proof(leaf_hash, None, leaf_hash, 0, 1)  # type: ignore[arg-type]


def test_non_sequence_proof_returns_false():
    leaf_hash = hash_leaf(b"x")
    # A generator is iterable but not a Sequence. Reject it: we need len-able
    # sequences so we can reason about proof shape.
    gen = (b"\x00" * 32 for _ in range(0))
    assert not verify_inclusion_proof(leaf_hash, gen, leaf_hash, 0, 1)  # type: ignore[arg-type]


def test_bytes_as_proof_returns_false():
    """A bytes object is technically a sequence of ints, not of hashes. Reject."""
    leaf_hash = hash_leaf(b"x")
    assert not verify_inclusion_proof(leaf_hash, b"raw bytes not a list", leaf_hash, 0, 1)  # type: ignore[arg-type]


def test_bytearray_inputs_accepted():
    leaves = [b"a", b"b"]
    leaf_hash, proof, root, idx, n = _inclusion_proof(leaves, 0)
    assert verify_inclusion_proof(
        bytearray(leaf_hash),
        [bytearray(p) for p in proof],
        bytearray(root),
        idx,
        n,
    )
