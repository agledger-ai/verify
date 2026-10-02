# Changelog

All notable changes to `@agledger/verify` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-09-30

This release targets AGLedger API 2.0 and reads nothing older. It is built on `@agledger/verify-core` 2.0.0. 1.7.0 was never published; its changes are part of this release.

### Breaking

- **A run without `--trust-anchor` passes flagged, never as trusted.** Reports carry a `verdict`: `trusted` (clean, every signing key anchored to a pin), `unanchored` (clean, no pin given) or `failed`. An unanchored pass keeps `ok: true` and exit `0`, and says so everywhere: the text headline is `[VERIFIED, NOT ANCHORED]` with lines saying it is not a trusted verdict and how to get a pin from the operator (a trusted pass is `[PASS]` and a failure `[FAIL]`, each with a line saying what it means), and the JSON carries `verdict: "unanchored"` and `keyTrust.status: "no_anchor"`. A gate that needs a trusted verdict reads `verdict` or passes `--trust-anchor`.
- **The org_admin_reads tree is RFC 9162.** `leaf_hash` is recomputed as hex(sha256(0x00 || cose_sign1)) and each tree head's root as the RFC 9162 root, through verify-core's `orgReadLeafHash` and `orgReadMerkleRoot`, the construction API 2.0 writes. A dump from an older engine fails `TENANT_READ_LEAF_HASH_MISMATCH` on every leaf. The re-exports `merkleRoot` and `verifyInclusion` are removed; `orgReadLeafHash`, `orgReadMerkleRoot` and `verifyOrgReadInclusion` (the audit-path walk for the Server's inclusion proofs) take their place (#27).
- **A dump directory must contain `vault_key_statements.ndjson`**, which every API 2.0 dump writes; without it the CLI exits `2`. `Dump` gains `keyStatements` and `DumpFiles` gains `keyStatements`.
- **`--require-out-of-band-keys` is `--require-supplied-keys`.** A key fetched from the Server comes from the database a key-registry attacker writes to, so "out of band" promised an independence it never gave. The old flag is refused with a message naming the new one. The export report's `key provenance` reads `supplied=` where it read `out-of-band=`, following verify-core's `keyProvenance.supplied`, and the `OutOfBandKeyEntry` re-export is `SuppliedKeyEntry`. The warning about embedded keys is replaced by the key-anchoring section.
- **`verifyVaultChains` and `verifyOrgAdminReadsChains` take the result of `walkDumpKeys`** in place of the raw `vault_signing_keys` rows, and `assembleReport` takes it as a third argument, so both passes grade against one verdict on each key. `VerifyReport` gains `verdict` and `keyTrust`; `ok` is false only for the `failed` verdict. `vault.optionalChecks` gains `key_anchoring`.
- `FailureCode` is verify-core's `FailureCode`, which now carries the read-log and key codes this package used to add itself.

### Added

- **Key anchoring on the dump path** (verify-core#20). `--trust-anchor sha256:<hex>` (repeatable) and `trustAnchors` in `VerifyDumpOptions` pin vault keys held out of band. The dump's key statements are walked by verify-core's `computeKeyTrust` in write order (`created_at`, then row id), and every row a vault key signs is graded against the result, with the engine's codes: a chain entry `CHAIN_SIGNING_KEY_UNANCHORED`, a vault checkpoint `CHECKPOINT_KEY_UNANCHORED`, a read-log leaf `TENANT_READ_KEY_UNANCHORED`, a read-log tree head `TENANT_CHECKPOINT_KEY_UNANCHORED`. An anchored key is held to the window its statements sign. A key reached only through a statement this host cannot compute is `undecided`, and what it signed is `CHAIN_UNSUPPORTED_ALGORITHM`. Findings about the statements (`KEY_STATEMENT_INVALID`, `KEY_CLOSURE_INVALID`, `CHAIN_KEY_WINDOW_DRIFT`) fail the dump and are listed under `key anchoring` in text and in `keyTrust.findings` in JSON.
- **`--distrusted-key` and `distrustedKeys`**, the operator's `VAULT_DISTRUSTED_KEYS` (`sha256:<hex>`, optionally `@<RFC 3339 instant>`), given once per key: what such a key stored from the instant on, or with none from the retirement a trusted key signed for it, counts for nothing in the walk. Given without a pin it is refused (exit `2`, or `TypeError` from the library) rather than ignored. `--distrusted-keys` is refused with a message naming `--distrusted-key`.
- Both flags apply to an `/audit-export` file too, passed to verify-core's `verifyAuditExport`, and the export JSON carries `verdict` beside verify-core's result.
- **The signed claims are checked against their rows, as the engine's scan checks them.** A vault checkpoint whose envelope does not decode as a claim, or whose signed position, tip hash, record subject or key id differs from its row, fails `CHECKPOINT_CLAIM_MISMATCH`. A read-log leaf whose signed position, previous-leaf hash, record id or record subject differs from its row fails `TENANT_READ_CLAIM_MISMATCH`. A read-log tree head whose signed size, root, count or key id differs fails `TENANT_CHECKPOINT_CLAIM_MISMATCH`. Each runs after the row, hash, index and root cross-checks and before anything about the key, so a key id column nulled beside a signed envelope is a claim mismatch rather than an unsigned row. The hash and root checks read the columns, so before this a rewritten column pair beside an intact envelope passed. `cborg` (the version verify-core pins) is now a runtime dependency, to read the claim as the engine does.
- **With a pin, the instant the install began signing is held to the signed activations too.** The unsigned-row rule (`CHAIN_ENTRY_UNSIGNED`, `CHECKPOINT_UNSIGNED`, `TENANT_READ_LEAF_UNSIGNED`, `TENANT_CHECKPOINT_UNSIGNED`) dates the install's first signature from the earliest `activated_at` in `vault_signing_keys`, an unsigned column. With `--trust-anchor`, the activations the anchored keys' statements sign count as well and the earliest stands, so stripping the column or moving it later no longer switches the rule off.
- **A pin over a dump with nothing signed by a key it anchors is not a trusted pass.** When `--trust-anchor` was walked but no vault entry verified under an anchored key, as for a dump of history written before the install began signing, `keyTrust.status` is `no_anchored_signature` and the verdict `unanchored`: exit `0`, headline `[VERIFIED, NOT ANCHORED]` with lines saying the pin was walked and no signature verified under a key it anchors. `vault.signedEntries` counts the entries whose signature verified, and `vault.optionalChecks.key_anchoring` is `not_checked` when a pin was given but no entry reached the anchoring check.
- **A vault row with no readable time fails closed.** An entry with a null, missing or unparseable `created_at` fails `CHAIN_MALFORMED_ENTRY` wherever its key's window or the start of signing needs one, where it used to skip the window check and read as unsigned history; nulling every `created_at` let entries signed by a distrusted key after its cutoff pass. An unsigned vault checkpoint, read-log leaf or tree head with no readable time once signing began fails its unsigned code.
- **Malformed rows are failure codes, not exceptions.** A null or dropped `payload` fails `CHAIN_PAYLOAD_BINDING_MISMATCH`; a key row with no `public_key` is no key, so what names it fails `CHAIN_SIGNATURE_MISSING_KEY`; a retyped `chain_key`, a null checkpoint or read-log `record_id` and a null tree-head `root_hash` no longer throw; a `tree_size` that is not a safe integer fails `TENANT_CHECKPOINT_LEAF_COUNT_MISMATCH`; rows whose `chain_position` or `leaf_index` is not a safe integer sort last and fail their position or index check.
- A vault checkpoint, read-log leaf or read-log tree head whose `cose_sign1` is null reads as empty bytes, so it fails `CHECKPOINT_CLAIM_MISMATCH`, `TENANT_READ_LEAF_HASH_MISMATCH` or `TENANT_CHECKPOINT_CLAIM_MISMATCH`. It threw out of the walk, which the CLI reported as exit `2` (could not verify) rather than as a failed verdict.
- A malformed pin or distrusted key, a distrusted key named twice, and a target that does not exist are exit `2`: no verdict was reached. A key statement row with no readable `created_at` is `KEY_STATEMENT_INVALID` (exit `1`), not a file the walk refuses. The flags, these refusals, their messages and the headlines are the same in the Python `agledger-verify` and in `agledger verify`.
- `walkDumpKeys` and `MAX_REPORTED_FAILURES` (the cap on each report section's failure list), the types `DumpKeyTrust` (what `walkDumpKeys` returns), `KeyTrustOptions`, `VaultChainOptions`, `KeyStatementDump` (a `vault_key_statements.ndjson` row) and `Verdict`, and re-exports of `computeKeyTrust`, `applyKeyTrust`, `parseTrustAnchors`, `parseDistrustedKeys`, `spkiSha256` and the `KeyTrust`, `KeyTrustReport`, `KeyTrustStatus` and `DistrustedKey` types. `KeyTrustStatus` is `walked`, `no_anchor` or `no_anchored_signature`; only `walked` on a clean run is the `trusted` verdict, and both of the others are `unanchored`.
- **A full dump re-verifies sealed agent signatures without `--agent-keys`.** The dump verifier takes the cert public keys the platform-ops chain signs, from a chain it has verified clean (hash chain, vault signatures and checkpoints) and only from entries whose vault signature checked, reading each key from the signed payload. They are used beside any `--agent-keys` / `agentKeys`, and the dump report counts them as `vault.certKeysFromChain`. The `agent sigs` line says when the keys came from the dump.

### Fixed

- **An unsigned row written once the install signs is a break, as the engine grades it.** The instant the install began signing is the earliest `activated_at` in `vault_signing_keys`, retired keys included; from then on every writer holds a registered key. An unsigned chain entry written at or after it, or after a signed entry in the same chain, fails `CHAIN_ENTRY_UNSIGNED`. An unsigned vault checkpoint written at or after it fails `CHECKPOINT_UNSIGNED`. On the cross-party read log, a leaf whose envelope kid is the unsigned sentinel `0000000000000000` fails `TENANT_READ_LEAF_UNSIGNED` when read at or after that instant or after a signed leaf in the same org's log, and an unsigned tree head written at or after it fails `TENANT_CHECKPOINT_UNSIGNED`. Each is checked after the row, hash, index and root cross-checks, so an existing tamper finding keeps its own code. Unsigned rows from before the first key activation stay reduced coverage, so an install that never registered a key still verifies. Before this, an unsigned entry or checkpoint anywhere was reduced coverage, which is what a writer holding no key, or a DBA nulling a signed row's key id, leaves behind.
- **A read-log leaf's signature is verified.** A leaf that names a real key now has its COSE_Sign1 signature checked under that key: one that does not verify, carries an all-zero signature, or does not decode fails `TENANT_READ_SIGNATURE_INVALID`, and a kid the key registry does not hold fails `CHAIN_SIGNATURE_MISSING_KEY`. Only the leaf hash and index were checked before, so a restamped leaf passed.
- **A chain-entry failure names the chain it is on.** An entry-level failure on a schema chain read `RecordRow schema:<orgId> pos N`, presenting the chain key as a record id; it now reads `Chain schema:<orgId> pos N`, as checkpoint failures already did. A failure on a per-record chain reads `Record <id> pos N` instead of the internal type name `RecordRow`.
- **An all-zero signature on a chain entry that names a signing key fails `CHAIN_SIGNATURE_INVALID`** rather than being graded unsigned.
- **The README said neither a dump nor an export carries cert public keys** (#26). A dump not scoped to one org does: each `EPHEMERAL_CERT_ISSUED` entry on the platform-ops chain signs its cert's `publicKeyJwk` (API 1.8.0 on). An org-scoped dump leaves that chain out, a per-record `/audit-export` does not include it, and a cert issued before 1.8.0 carries only its thumbprint. The README and `--help` now say so.

### Changed

- The export path walks key statements in write order too: every API 2.0 export carries each statement's `id` and `createdAt`, so an export and a dump of the same Server are walked alike and a trusted key's later admissions date its window as the Server's do.
- Requires `@agledger/verify-core` 2.0.0.
- The conformance corpus is regenerated from agledger-api 2.0.0 (`e690979c`): the dump slice carries `vault_key_statements.ndjson` in every vector and adds the key-statement, unsigned-row and RFC 9162 vectors. Every vector passes as its manifest expects, those that pin `trustAnchors` included. Pinned on the Server's current key, the three registry column-edit vectors (`chain-key-expired`, `chain-key-not-yet-active`, `valid-rotation-boundary`) read as `KEY_CLOSURE_INVALID` or `CHAIN_KEY_WINDOW_DRIFT` rather than the window codes their manifest names, since a pinned walk holds entries to the signed window; unpinned they give their manifest verdicts.
- The agent-signature line reads `no key for their cert` where it read `no key supplied for their cert`, since a key can now come from the dump.
- On a failed run the agent-signature line says its counts stop at the first break in each chain, since nothing past a break is read; it used to say `none on the chain` when signatures sat beyond the break.
- An `/audit-export` file verify-core refuses as malformed is reported with the file's name, and the note on the `--keys` file's shape is added only when `--keys` was given and is what verify-core refused. It was added to every refusal, with or without `--keys`.
- A vault row with no `cose_sign1` is described as carrying no signed envelope (an engine that predates it, or a removed column) rather than as a "pre-2.0 dump shape".

## [1.6.0] - 2026-09-21

### Fixed

- **Conformance corpus regenerated from the tagged 1.8.0 engine** (`apiGitSha 3948cc68`, the `v1.8.0` commit), replacing a corpus generated at API 1.3.4. The export slice goes from 23 to 32 vectors and the dump slice from 12 to 18, and the additions cover this release's own work: `export/actor-attribution-mismatch.json` and `dump/chain-actor-attribution-mismatch` both expect `CHAIN_ACTOR_ATTRIBUTION_MISMATCH`, and `export/agent-signature-invalid.json` expects `CHAIN_AGENT_SIGNATURE_INVALID`. The runner now maps the manifest's `agentKeysFile` to the verifier's agent-key input; without it that vector ran with no agent keys, reported `skipped_no_input`, passed, and failed the suite on a check that never executed.

- **Actor attribution is verified, not displayed on trust.** An audit export's own verification guide names `actorDisplayName`, `actorOwnerType` and `humanReadableLabel` as unsigned display projections and tells the auditor that the attribution to rely on is the `actorId`/`actorOwnerId` UUID. Those two, and `actorRole`, are signature-covered in the COSE protected header (CWT_Claims label 15, private label -65539), and nothing compared them against it: an export or dump row could be re-attributed to another actor, changing nothing else, and still verify with out-of-band keys. They are now cross-checked per entry, and a divergence fails the new `CHAIN_ACTOR_ATTRIBUTION_MISMATCH`. This runs on a dump directory and on an `/audit-export` file; the dump carries `actor_key_id`, `actor_role` and `actor_owner_id` on every row, so it always applies there. The text report's `note` line no longer tells the reader that attribution is the signed UUID without saying whether this run checked it: it now states that the attribution was cross-checked and agrees, or that the export carried no signed actor claim to check it against. Requires `@agledger/verify-core` 1.5.0.

### Added

- **`agledger-verify --agent-keys <file>`** re-verifies, offline, the agent signatures sealed in chain entries, on a dump directory and on an `/audit-export` file. The file holds the Ed25519 public keys of agent ephemeral certs (the `publicKeyJwk` an agent sent at cert exchange, also the `cnf.jwk` claim in its `certJws`) as one JWK, a list of JWKs, or a `{keys: [...]}` JWK Set, where an entry may wrap its key as `{publicKeyJwk: {...}}`: the same shapes `agledger verify --agent-keys` takes. An entry whose sealed cert thumbprint names one of the keys has its `predicate.on_behalf_of.agent_signature` checked, and one that does not verify fails `CHAIN_AGENT_SIGNATURE_INVALID`. A file with no keys, or with anything that is not an Ed25519 JWK, is exit 2 with a message saying what is wrong with it.
- Both reports say whether the check ran and count agent signatures present and verified: a new `agent sigs` / `agent signatures` line in text, and in JSON `optionalChecks.agent_signature` plus `agentSignatures` (on the dump report, under `vault`). Without `--agent-keys` the check is reported as not run and no verdict changes. The text line says `all re-verified` only when every agent signature was; otherwise it says how many were NOT verified, and when keys were supplied but none matches a sealed cert thumbprint it says that instead of asking for `--agent-keys`.
- The dump report's `vault` gains `optionalChecks`, saying which input-gated checks (payload binding, OIDC actor, key validity window, agent signature) ran on at least one chain.
- `verifyDumpStreaming`, `verifyDump` and `verifyVaultChains` take an options argument with `agentKeys`. `buildAgentKeyRegistry` and the `AgentPublicKeyJwk`, `AgentKeyRegistry`, `OptionalCheck`, `CheckApplicability` and `VerifyDumpOptions` types are exported.

### Changed

- `LICENSE` follows SDK License Template 1.9: section 1 says AGLedger LLC does not receive, inspect or use the data you process through your deployment and collects no product usage information from it; section 7 names AGLedger and Settlement Signal as trademarks of AGLedger LLC; section 8 refers to issued or pending U.S. patents.
- Requires `@agledger/verify-core` 1.5.0, which adds the agent-signature check and holds a row copy of `on_behalf_of` or `traceparent` to the value the entry signed: a rewritten or added row copy now fails `CHAIN_PAYLOAD_BINDING_MISMATCH` instead of verifying, in a dump and in an export.

- The conformance corpus is regenerated at API 1.8.0, dump slice included. Same vectors and expected codes as the 1.7.0 corpus, and all pass.
- Verified against a full vault dump from a live API 1.8.0 instance: record-lifecycle entries that sign the internal state (`state`, `previousState`, `newState`) beside the display status, the new `AUTH_KEY_ROTATED` entry on the platform-ops chain, and cert-signed and delegated creates all pass, and a rewritten `AUTH_KEY_ROTATED` payload or internal state fails `CHAIN_PAYLOAD_BINDING_MISMATCH`. No verification change was needed for them.

## [1.5.3] - 2026-09-10

### Changed

- **LICENSE section 6 names the ciphers this package line ships**: Ed25519 (EdDSA), ECDSA P-256 with SHA-256, HMAC-SHA-256, AES-256-GCM, HKDF-SHA-256 and SHA-256. X25519 is gone from the list with the federation encryption key the engine no longer has. The LICENSE file is the only shipped byte that moved.

## [1.5.2] - 2026-08-30

Documentation only. Verification behaviour is identical to 1.5.1.

### Added

- The README documents how to install the package.

### Changed

- Comments and documentation no longer point at resources outside this repository.

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
