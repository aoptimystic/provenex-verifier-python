# Test vectors

Static fixtures for the standalone Provenex verifier.

## Files

| File | Purpose |
| ---- | ------- |
| `ed25519_public_key.pem` | Public key for `valid_minimal_receipt.json`, `valid_full_receipt.json`, and `tampered_field_receipt.json`. |
| `valid_minimal_receipt.json` | A minimal receipt at schema 2.5.0 with a valid Ed25519 signature. |
| `valid_full_receipt.json` | A richer receipt with sources, access-control decisions, and a transparency-log block. |
| `tampered_field_receipt.json` | `valid_full_receipt.json` with `summary.overall_status` flipped after signing. Verification must fail. |
| `hmac_receipt.json` | An HMAC-SHA256 signed receipt. Verification must fail with `unsupported signature algorithm`. |

## Regenerating

```
python test-vectors/generate.py
```

This overwrites every file with a fresh keypair. The private key is not persisted.

## Stability guarantee

These vectors are versioned alongside the library. Any change to canonicalization or signature format that breaks a previously valid receipt is a breaking change and requires a major version bump.
