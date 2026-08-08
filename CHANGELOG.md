# Changelog

All notable changes to `@agledger/verify` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.5.1] - 2026-08-07

### Fixed

- **A FIPS-locked host no longer reports an intact Ed25519 dump as tamper**, via `@agledger/verify-core`. The FIPS provider carries no EdDSA, so the runtime refused to compute the signature and the refusal was reported as `CHAIN_SIGNATURE_INVALID` on every entry. It now reports `CHAIN_UNSUPPORTED_ALGORITHM`, naming the provider as the cause and pointing at an unrestricted host. Still `[FAIL]` and exit 1, because an unverified chain is not a verified one, but no longer grounds for a tamper investigation (agents#113). The refusal a real provider performs is at key LOAD, one step earlier than first fixed, so a key that will not load is now classified from its OID; verified against the same corpus and container that produced the original report.
- **Checkpoint failure messages stop asserting a signature failed when it was never checked.** The `CHAIN_UNSUPPORTED_ALGORITHM` code was already routed correctly at both checkpoint sites, but the message read "COSE_Sign1 signature does not verify (unsupported-key-algorithm)", which says the opposite of what the code means. It now reads "signature could NOT BE CHECKED" plus the reason and the remedy.

### Changed

- **Report text no longer uses em-dashes**, in the help header, the unsigned-projection note, and the tree-head fork message. Wording only; every verdict, code, and exit status is unchanged.

### Packaging

- **Source maps are no longer published.** `dist/**/*.map` shipped with `sources` pointing at `../src/*.ts` and no `sourcesContent`, and `src/` is not in the tarball, so they resolved to nothing. The build no longer emits them at all, so no shipped `.js` or `.d.ts` carries a `sourceMappingURL` comment pointing at a map the tarball does not contain (agents#114).
- **`bugs` added to package.json.**

## [1.5.0] - 2026-08-07

### Fixed

- **Vault checkpoints join on `chain_key`, so a healthy schema chain no longer fails the whole dump.** A schema chain's checkpoint carries a derived UUIDv8 in `record_id`, because the engine needs a non-null uuid for a chain whose rows have none. Grouping checkpoints by that column stranded them: a stock Compose install, untouched, returned `[FAIL]` and exit 1 with `CHECKPOINT_ROW_MISSING`, which is a tamper alarm for any audit gate wired to the exit code. Checkpoints now group on the producer's `chain_key`, falling back to `record_id` so dumps taken before the producer emitted it verify exactly as they did before (agents#103).
- **Failures name a schema chain by its chain key.** The message said `RecordRow <uuidv8>`, sending an auditor to `/v1/records/{id}` for a 404 with no explanation. It now reads `Chain schema:<orgId>` (agents#103).

### Changed (widened union, via `@agledger/verify-core` 1.3.0)

- **`CHAIN_KEY_NOT_YET_ACTIVE`** is reported for an entry written BEFORE its signing key's activation; `CHAIN_KEY_EXPIRED` now means the retirement side only. Previously both directions reported "expired", sending a consumer to investigate rotation when the real condition is a backdated entry or clock skew. Verdicts are unchanged (agents#112).

## [1.4.0] - 2026-08-05

Signing-agility wave 2: verifies ES256 chains end to end (chain walk, vault checkpoints, org-admin-reads signed tree heads) via `@agledger/verify-core` 1.2.0. Ed25519 chains verify byte-identically to 1.3.1.

### Added

- **ES256 verification** across every surface this package checks, dispatched from the trusted key's SPKI, never the envelope header. Algorithms past this build (ES384, ES512, ES256K) still fail closed as `CHAIN_UNSUPPORTED_ALGORITHM`.

### Changed

- **Conformance corpus regenerated from engine 1.3.4 @ `ed3369ab`** (the api R2 signing-agility build) and re-pinned via `CORPUS-LOCK.json`. Both slices gain the ES256 wave: `export/valid-es256` + `dump/valid-es256` (real ES256 engine output, must pass), `es256-signature-invalid`, and `es256-header-alg-mismatch` (a valid ES256 signature under an EdDSA header reads as `CHAIN_ALG_MISMATCH`, tamper class).

## [1.3.1] - 2026-08-05

### Fixed

- **An empty-string `signing_key_id` is no longer treated as unsigned.** Takes `@agledger/verify-core` 1.1.1 for the chain walk, and applies the same rule at both local checkpoint sites (vault checkpoints and org-admin-reads signed tree heads): only null/undefined means unsigned, so a tampered `signing_key_id: ""` now fails `CHAIN_SIGNATURE_MISSING_KEY` instead of silently skipping the signature check.

## [1.3.0] - 2026-08-05

The verifier forward-compatibility floor (with `@agledger/verify-core` 1.1.0). Legitimate Ed25519 dumps verify identically; what changes is fail-closed classification of tampered and non-Ed25519 inputs.

### Changed

- **Takes `@agledger/verify-core` `^1.1.0`**, inheriting the key-bound algorithm dispatch, the tamper-class `CHAIN_ALG_MISMATCH`, the fail-closed `CHAIN_UNSUPPORTED_ALGORITHM`, the signed-kid binding (`CHAIN_SIGNING_KEY_DRIFT`), untagged-COSE_Sign1 rejection, and the key-length-derived unsigned sentinel. See that package's 1.1.0 changelog for the full contract.
- **Checkpoint signature checks fail closed on every non-ok outcome.** Both the vault-checkpoint and the org-admin-reads signed-tree-head sites previously passed an all-zero signature on a checkpoint that claims a `signing_key_id` (the `'unsigned'` outcome slipped between the two handled failure cases). Any non-ok outcome now fails: `CHECKPOINT_SIGNATURE_INVALID` / `TENANT_CHECKPOINT_SIGNATURE_INVALID`, or `CHAIN_UNSUPPORTED_ALGORITHM` when the key's algorithm is beyond this build.
- **`vault_signing_keys.algorithm` is now plumbed into verification.** The dump's declared algorithm is cross-checked against the key material itself; a registry row that lies about its own key fails `CHAIN_ALG_MISMATCH`. The declared string never selects the code path.
- Conformance corpus refreshed from engine 1.3.4, including the new `chain-signing-key-drift` and `chain-alg-registry-lie` dump vectors.

## [1.2.0] - 2026-08-01

A full-installation dump could not be verified at all. The loader read each NDJSON file into a single string, so any vault past Node's ~512 MB string cap died in about a second with a raw `Cannot create a string longer than 0x1fffffe8 characters`. Small demo vaults verified fine, which is why this survived a shipped release: the first deployment large enough to need the tool for a real audit is the one that finds it. Testbed F-811 hit it with 545k `audit_vault` rows (1.18 GB NDJSON), roughly a quarter of realistic operation for one mid-size org.

### Fixed

- **Reading is chunked**, so file size is bounded by disk rather than by the string cap. Verification streams too, one chain group at a time, because materializing 1.18 GB of NDJSON as objects only trades a clean error for an OOM. Peak memory is now the largest single chain instead of the whole vault.
- Streaming depends on the producer's `ORDER BY record_id, chain_position`, which has held since the format existed. That assumption is checked rather than trusted: a `chain_key` that reappears after its group closed is reported as `UNSUPPORTED_FORMAT` with an instruction to re-export, instead of silently verifying a partial chain and reporting clean.

### Changed

- **Exit codes split.** `1` is verification FAILED, `2` is could NOT verify. Both were `1`, so a missing or oversized dump was indistinguishable from a broken chain to any gate wired to "nonzero means tampering". `--report-format json` now emits JSON for input errors as well, instead of a bare line of prose. A script asserting `exitCode === 1` on a bad path will now see `2`.
- **Failure lists are capped**, with the true total in a new `failureCount` field on `VaultChainsReport` and `TenantAdminReadsReport`. Reaching large vaults made a second problem reachable with them: a systemic fault yields one failure per entry, and the 621 MB reproduction produced 462,002 failures and 51 MB of stdout. That report is now 114 KB. A consumer reading `failures.length` as the count under-reports above 1000 failures.

### Notes

- `runCli` and `loadDump` keep their signatures. The read path stayed synchronous specifically so lifting the size ceiling would not force an async breaking change.
- `loadDump` + `verifyDump` still work and produce the same report. `verifyDumpStreaming` is the new preferred entry point and is what the CLI uses.
- `Dump`, `VaultEntryDump`, and the companion wire types are unchanged. No dump-format change, so no coordination with the dump tool or the conformance corpus.
- Tests cover chunk-boundary reassembly, multi-byte characters split across a boundary, report-for-report equivalence with the in-memory path across all nine conformance dump vectors, the re-ordered-dump refusal, and the exit-code split. The size case itself is opt-in via `AGLEDGER_VERIFY_LARGE_FILE_TEST=1`, since it wants about 1 GB of disk.

Closes #14. Refs cross-repo agledger-agents#102.

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
