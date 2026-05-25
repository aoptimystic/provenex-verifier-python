"""Canonical JSON tests."""

from __future__ import annotations

import json

import pytest

from provenex_verifier import canonicalize


def test_basic_canonicalization():
    assert canonicalize({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_strips_signature_block():
    receipt = {"a": 1, "signature": {"algorithm": "ed25519", "value": "deadbeef"}}
    assert canonicalize(receipt) == b'{"a":1}'


def test_nested_keys_sorted_at_every_level():
    receipt = {"outer": {"z": 1, "a": 2, "m": {"y": 1, "b": 2}}, "first": True}
    assert canonicalize(receipt) == b'{"first":true,"outer":{"a":2,"m":{"b":2,"y":1},"z":1}}'


def test_non_ascii_preserved_as_utf8():
    receipt = {"q": "café “smart” 中文"}
    result = canonicalize(receipt)
    decoded = result.decode("utf-8")
    assert "café" in decoded
    assert "“smart”" in decoded
    assert "中文" in decoded
    assert "\\u" not in decoded  # no unicode escapes


def test_no_whitespace_between_separators():
    result = canonicalize({"a": [1, 2, 3], "b": {"c": 4}})
    assert b" " not in result


def test_nan_rejected():
    with pytest.raises(ValueError):
        canonicalize({"x": float("nan")})


def test_infinity_rejected():
    with pytest.raises(ValueError):
        canonicalize({"x": float("inf")})


def test_neg_infinity_rejected():
    with pytest.raises(ValueError):
        canonicalize({"x": float("-inf")})


def test_non_mapping_rejected():
    with pytest.raises(TypeError):
        canonicalize(["not", "a", "dict"])  # type: ignore[arg-type]


def test_unserializable_value_raises_type_error():
    with pytest.raises(TypeError):
        canonicalize({"x": object()})


def test_input_not_mutated():
    receipt = {"a": 1, "signature": {"algorithm": "ed25519", "value": "deadbeef"}}
    snapshot = json.dumps(receipt, sort_keys=True)
    canonicalize(receipt)
    assert json.dumps(receipt, sort_keys=True) == snapshot


def test_idempotent_round_trip():
    receipt = {"b": 1, "a": [3, 2, 1], "c": {"nested": True}}
    first = canonicalize(receipt)
    second = canonicalize(json.loads(first.decode("utf-8")))
    assert first == second


def test_signature_only_stripped_at_top_level():
    # A nested "signature" key (e.g. inside an inner dict) must be preserved.
    receipt = {"a": {"signature": "inner"}, "b": 2}
    assert canonicalize(receipt) == b'{"a":{"signature":"inner"},"b":2}'
