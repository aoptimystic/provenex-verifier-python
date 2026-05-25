# Contributing

Thank you for your interest in contributing. The verifier is intentionally small: scope discipline is the project's defining property.

## Ground rules

1. **No new runtime dependencies.** The library depends on `cryptography` and nothing else. Proposals to add dependencies require a clear rationale and will be considered carefully.
2. **No network access at runtime.** The library must run unmodified in an air-gapped environment.
3. **No bidirectional dependency on `provenex-core`.** The verifier implements the receipt-format spec directly. If the spec changes, this library changes; if `provenex-core` adds an unrelated feature, this library does not.
4. **Spec changes are major versions.** Any change that breaks a previously valid receipt requires a major version bump and a corresponding CHANGELOG entry.

## Development

```
git clone https://github.com/provenex/provenex-verifier-python
cd provenex-verifier-python
python -m pip install -e ".[test]"
make test
```

Tests must:

* Maintain 100% line and branch coverage on the `provenex_verifier` package.
* Complete in under 5 seconds (`pytest -xvs`).
* Pass on Python 3.9 through 3.13.

## Adding a test

Negative cases are first-class. Every new validation path should ship with a test for the failure mode it guards.

## Pull requests

* Open a PR against `main`.
* Reference the issue or use case in the description.
* The CI matrix must pass on all supported Python versions before merge.

## Releases

Releases are tagged `vX.Y.Z`, signed with Sigstore cosign, and published to PyPI with an SBOM. The first stable release is v1.0.0. See [CHANGELOG.md](CHANGELOG.md) for version history.
