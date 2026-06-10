# Changelog

All notable changes to `@agledger/verify` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.6] - 2026-06-10

### Changed

- **License re-sync.** `LICENSE` is now a verbatim copy of the canonical AGLedger SDK license template **v1.5**: §7 trademarks trimmed to **AGLedger + Settlement Signal (pending)** (removed the retired "Agentic Ledger" / AOAP claims), §6 export language modernized to ENC §740.17(b)(1) mass-market self-classification, and §1 carries the no-inspection / no-training / no-usage-data representation.
- No code changes; republished so the distributed tarball carries the corrected license text.

## [0.1.5] - 2026-06-04

### Changed

- The EXPORT-kind conformance corpus (`testdata/conformance/export/` + `manifest-export.json`) is now exercised in the test suite — previously only the DUMP-kind vectors ran, so the 18 shipped export vectors were dead weight. The new block runs each vector through `verifyAuditExport` (the same code path the CLI/library uses for single `/audit-export` documents) and asserts pass/fail, `brokenAt.code`, and `brokenAt.position`. The export manifest is hard-asserted present so a missing corpus fails loud.
- Corrected the README corpus-regeneration instructions: removed the bogus `pnpm generate:corpus` step (no such script; this repo uses npm and has no local generator). The corpus is produced and owned by `agledger-api` via `scripts/generate-conformance-corpus.ts`; refresh there and copy `export/`, `dump/`, and both manifests into `testdata/conformance/`.
- Refreshed the `@agledger/verify-core` dependency range to `^0.1.7` (lockfile resolves the latest published verify-core).

## [0.1.4] - 2026-06-04

No functional change. First release published from CI with **build provenance** via npm trusted publishing (OIDC) — npm attaches a Sigstore provenance attestation automatically; verify with `npm audit signatures`. A CycloneDX SBOM is attached to the release. This package now lives in its own source-of-truth repo `agledger-ai/verify` and resolves `@agledger/verify-core@0.1.4`.

## [0.1.3] - 2026-05-29

### Changed

- Rebuilt on `@agledger/verify-core@^0.1.3`, inheriting export-path binding-integrity (F-731) and the new `not-checked` signature state (F-732). No change to the dump-verifier API or CLI.

## [0.1.2] - 2026-05-28

Republished against `@agledger/verify-core` 0.1.2 — picks up the F-698 OOB-key polymorphism and the temporal-axis tightening (export `signingKeyWindows` no longer clobbers caller-supplied OOB windows). No functional change in the dump verifier itself. Now also re-exports the new `OutOfBandKeyEntry` type so dump consumers don't need a second dep to type their OOB key catalogue.

## [0.1.1] - 2026-05-28

Republished against `@agledger/verify-core` 0.1.1 — no functional change in the dump verifier itself. The shared core now also exercises `oidc_actor` and `key_temporal` on the per-record export path; the full-vault dump path here is unchanged.

## [0.1.0] - 2026-05-27

Initial release. Full-vault offline dump verifier for AGLedger audit dumps produced by `vault-dump.sh`. Adopted from the agledger-api `tools/agledger-verify/` package and refactored onto `@agledger/verify-core` so the chain walk, COSE_Sign1 decode, and Ed25519 verification share a single body of logic with the SDK / CLI / MCP. Adds dump-only checks: binding-integrity, OIDC-actor cross-check, temporal key-validity, vault checkpoints, org_admin_reads Merkle/STH/fork.
