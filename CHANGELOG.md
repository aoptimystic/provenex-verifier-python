# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-05-25

Initial release.

### Added

* `verify_receipt(receipt, public_key)` returning `VerificationResult`.
* `canonicalize(receipt)` exposed publicly so callers can audit the canonical-payload step.
* `verify_inclusion_proof(leaf_hash, proof, tree_root, leaf_index, tree_size)` for RFC 6962 Merkle inclusion proofs.
* `provenex-verify` CLI with stdin support and standard exit codes (0/1/2).
* Static test vectors under `test-vectors/` plus a generator script.
* 100% line and branch coverage on the verifier modules.
* CI matrix across Python 3.9, 3.10, 3.11, 3.12, and 3.13.

### Design notes

* Ed25519 only. HMAC receipts are rejected with a clear error rather than silently accepted, because HMAC is symmetric and out of scope for third-party verification.
* No network calls. Safe to run in air-gapped environments.
* No dependency on `provenex-core`. The library implements the receipt-format spec directly.
* Single runtime dependency: `cryptography` (for Ed25519 primitives).

[1.0.0]: https://github.com/aoptimystic/provenex-verifier-python/releases/tag/v1.0.0
