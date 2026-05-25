"""CLI tests."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from provenex_verifier import cli


def _write(path: Path, content) -> Path:
    if isinstance(content, (bytes, bytearray)):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def test_valid_receipt_exits_zero(tmp_path, signed_receipt, public_key_pem, capsys):
    rcpt = _write(tmp_path / "r.json", json.dumps(signed_receipt))
    key = _write(tmp_path / "k.pem", public_key_pem)
    rc = cli.main([str(rcpt), "--public-key", str(key)])
    captured = capsys.readouterr()
    assert rc == 0
    assert "valid:     True" in captured.out
    assert "signer:    provenex-core/1.0.0" in captured.out


def test_tampered_receipt_exits_one(tmp_path, signed_receipt, public_key_pem, capsys):
    tampered = dict(signed_receipt)
    tampered["summary"] = {**signed_receipt["summary"], "overall_status": "BLOCK"}
    rcpt = _write(tmp_path / "r.json", json.dumps(tampered))
    key = _write(tmp_path / "k.pem", public_key_pem)
    rc = cli.main([str(rcpt), "--public-key", str(key)])
    captured = capsys.readouterr()
    assert rc == 1
    assert "valid:     False" in captured.out
    assert "signature does not match" in captured.err


def test_missing_receipt_exits_two(tmp_path, public_key_pem, capsys):
    key = _write(tmp_path / "k.pem", public_key_pem)
    rc = cli.main([str(tmp_path / "missing.json"), "--public-key", str(key)])
    captured = capsys.readouterr()
    assert rc == 2
    assert "could not read receipt" in captured.err


def test_missing_public_key_exits_two(tmp_path, signed_receipt, capsys):
    rcpt = _write(tmp_path / "r.json", json.dumps(signed_receipt))
    rc = cli.main([str(rcpt), "--public-key", str(tmp_path / "missing.pem")])
    captured = capsys.readouterr()
    assert rc == 2
    assert "could not read public key" in captured.err


def test_malformed_json_exits_two(tmp_path, public_key_pem, capsys):
    rcpt = _write(tmp_path / "r.json", "{not json")
    key = _write(tmp_path / "k.pem", public_key_pem)
    rc = cli.main([str(rcpt), "--public-key", str(key)])
    captured = capsys.readouterr()
    assert rc == 2
    assert "not valid JSON" in captured.err


def test_stdin_input(tmp_path, signed_receipt, public_key_pem, capsys):
    key = _write(tmp_path / "k.pem", public_key_pem)
    stdin = io.StringIO(json.dumps(signed_receipt))
    rc = cli.main(["-", "--public-key", str(key)], stdin=stdin)
    captured = capsys.readouterr()
    assert rc == 0
    assert "valid:     True" in captured.out


def test_quiet_suppresses_output(tmp_path, signed_receipt, public_key_pem, capsys):
    rcpt = _write(tmp_path / "r.json", json.dumps(signed_receipt))
    key = _write(tmp_path / "k.pem", public_key_pem)
    rc = cli.main([str(rcpt), "--public-key", str(key), "--quiet"])
    captured = capsys.readouterr()
    assert rc == 0
    assert captured.out == ""
    assert captured.err == ""


def test_quiet_failure_still_exits_one(tmp_path, signed_receipt, public_key_pem, capsys):
    tampered = dict(signed_receipt)
    tampered["summary"] = {**signed_receipt["summary"], "overall_status": "BLOCK"}
    rcpt = _write(tmp_path / "r.json", json.dumps(tampered))
    key = _write(tmp_path / "k.pem", public_key_pem)
    rc = cli.main([str(rcpt), "--public-key", str(key), "--quiet"])
    captured = capsys.readouterr()
    assert rc == 1
    assert captured.out == ""


def test_missing_required_arg_exits_two(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["receipt.json"])
    assert exc.value.code == 2


def test_version_flag_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "provenex-verify" in captured.out


def test_warnings_print_to_stderr(tmp_path, sign_receipt, public_key_pem, capsys):
    """Verify warnings (e.g. missing issued_at) flow to stderr."""
    receipt = sign_receipt({})
    rcpt = _write(tmp_path / "r.json", json.dumps(receipt))
    key = _write(tmp_path / "k.pem", public_key_pem)
    rc = cli.main([str(rcpt), "--public-key", str(key)])
    captured = capsys.readouterr()
    assert rc == 0
    assert "warning:" in captured.err
    assert "signed_at: (unknown)" in captured.out
    assert "signer:    (missing)" in captured.out
