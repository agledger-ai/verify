# Changelog

All notable changes to `@agledger/verify` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.3] - 2026-05-29

### Changed

- Rebuilt on `@agledger/verify-core@^0.1.3`, inheriting export-path binding-integrity (F-731) and the new `not-checked` signature state (F-732). No change to the dump-verifier API or CLI.

## [0.1.2] - 2026-05-28

Republished against `@agledger/verify-core` 0.1.2 — picks up the F-698 OOB-key polymorphism and the temporal-axis tightening (export `signingKeyWindows` no longer clobbers caller-supplied OOB windows). No functional change in the dump verifier itself. Now also re-exports the new `OutOfBandKeyEntry` type so dump consumers don't need a second dep to type their OOB key catalogue.

## [0.1.1] - 2026-05-28

Republished against `@agledger/verify-core` 0.1.1 — no functional change in the dump verifier itself. The shared core now also exercises `oidc_actor` and `key_temporal` on the per-record export path; the full-vault dump path here is unchanged.

## [0.1.0] - 2026-05-27

Initial release. Full-vault offline dump verifier for AGLedger audit dumps produced by `vault-dump.sh`. Adopted from the agledger-api `tools/agledger-verify/` package and refactored onto `@agledger/verify-core` so the chain walk, COSE_Sign1 decode, and Ed25519 verification share a single body of logic with the SDK / CLI / MCP. Adds dump-only checks: binding-integrity, OIDC-actor cross-check, temporal key-validity, vault checkpoints, org_admin_reads Merkle/STH/fork.
