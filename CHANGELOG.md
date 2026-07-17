# Changelog

All notable changes to `@agledger/verify` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.1.1] - 2026-07-16

Docs and tooling. No verification or wire-format change.

### Fixed

- README and package links no longer send readers into the private `agledger-api` repo (cross-repo #99); they point at the public source repo instead. Removed the refactoring-history note from the npm package description.

### Changed

- Refreshed the lockfile to in-range latest (`@agledger/verify-core` 1.0.2, plus dev tooling).
- Upgraded the TypeScript devDependency to `^7.0.2`. Build, typecheck, tests, and publint/attw all pass under 7.0.2.

## [1.1.0] - 2026-07-06

Closes cross-repo verify#8: the CLI could not perform the out-of-band-keyed verification the README prescribes, so a key-substituted export (full re-sign with an attacker key embedded in the document) returned `[PASS]`.

### Added

- **`--keys <file>`**: supply out-of-band public keys for an `/audit-export` file. Accepts a `{keyId: SPKI-DER-base64}` map, a `[{keyId, publicKey, ...}]` list, or the raw `GET /v1/verification-keys` response envelope (`.data` unwrapped automatically, same behavior as `agledger verify --keys`). Merged over any keys embedded in the export.
- **`--require-out-of-band-keys`**: refuse keys embedded in the export; the key-substitution conformance vector now fails closed from the CLI (`CHAIN_KEY_POLICY_VIOLATION` at the swapped entry).
- **`--require-key-id <id>`**: reject an otherwise-valid export signed by a retired or unexpected key.
- The text report now prints an explicit WARNING when a PASS was earned only against keys embedded in the export itself (out-of-band=0), instead of leaving the trust assumption encoded in the provenance counters.
- README: "Independent verification of an export" section with the fetch-keys-out-of-band workflow.

### Notes

- The key-policy flags apply to `/audit-export` files only; a dump directory carries its own signed key history and rejects them with a usage error.
- Default behavior is unchanged: without `--keys`, embedded keys are still trusted (documented corpus behavior), and all previously passing/failing vectors keep their results.


## [1.0.2] - 2026-06-29

### Changed

- Docs only: removed em-dashes from the README prose and the package.json description (cross-repo #98 writing-style sweep). Rewrote each sentence rather than swapping the glyph. No verification, exit-code, or wire-format change.

## [1.0.1] - 2026-06-22

### Added

- **Unsigned-projection warning on the audit-export verdict** (cross-repo #96 / api#769). A green `[PASS]` over a `/v1/records/{id}/audit-export` dump no longer silently vouches for spoofable display labels. When the export self-describes unsigned projection fields (`verificationGuide.unsignedFields`), the verdict now prints a non-fatal `note:` naming them and stating that attribution is the signed `actorOwnerId`/`actorId` UUID, not these labels. The `--report-format json` output carries the machine-readable `unsignedProjectionFields` array. No change to chain verification or exit codes.

### Changed

- Bumped `@agledger/verify-core` to `^1.0.1` (provides `unsignedProjectionFields`).

## [1.0.0] - 2026-06-20

### Changed

- **1.0.0 GA.** Version promoted to 1.0.0 to align with the AGLedger API v1.0.0 GA and the published package line. Bumped `@agledger/verify-core` to `^1.0.0` (now also GA at 1.0.0). No verifier-logic or CLI-surface changes from 0.1.6 — the dump-verification behavior and exit codes are unchanged.

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
