# Security policy

## Reporting a vulnerability

Email **contact@provenex.ai** with the subject line `[verifier] security`.

Please include:

* A description of the issue and its impact.
* Steps to reproduce or a proof-of-concept.
* Affected versions.
* Your name or handle if you would like credit; otherwise we will publish the disclosure anonymously.

Do **not** open public GitHub issues for security reports.

## Response targets

| Step | Target |
| ---- | ------ |
| Acknowledgement of report | 2 business days |
| Initial triage and severity assessment | 5 business days |
| Fix or mitigation in a tagged release | Critical: 7 days. High: 30 days. Lower: best-effort. |
| Public disclosure | Coordinated with reporter; default 90 days after fix is shipped. |

## Scope

In scope:

* Bugs that cause `verify_receipt` to return `valid=True` for a receipt whose signature does not match its canonical payload.
* Bugs that cause `verify_inclusion_proof` to return `True` for an invalid proof.
* Canonicalization mismatches that would let a producer and verifier disagree on the signed bytes.
* Resource-exhaustion attacks reachable through public APIs (CPU, memory, file descriptors) on adversarial input.

Out of scope:

* Issues that require an attacker already holding the issuer's private key.
* Policy interpretation, trajectory validation, or anything beyond cryptographic envelope verification: this library deliberately does not perform those checks.
* Bugs in upstream `cryptography` (please report to PyCA).

## Supported versions

We support the latest minor release of the `1.x` line. Security fixes for older minor releases are best-effort.

## Cryptographic primitives

* Ed25519 via [pyca/cryptography](https://github.com/pyca/cryptography). Constant-time signature verification at the primitive level.
* SHA-256 (stdlib `hashlib`) for RFC 6962 Merkle hashing.

There is no random-number generation, no key derivation, and no symmetric encryption in this library. Public-key loading is offline (no key-fetching).
