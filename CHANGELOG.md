# Changelog

All notable changes to `@agledger/verify` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [2.2.0] - 2026-11-18

Requires `@agledger/verify-core` 2.2.0.

### Added

- **`--allow-after-retirement`.** A sealed federation message signed by a peer key more than 300 seconds after that key's retirement fails `CHAIN_FEDERATION_WIRE_INVALID`, as the verifier now holds it. The flag accepts such a message and counts it as `after-retirement` in the peer-message line, for a peer that kept signing briefly after rotating because its process had not restarted. It applies to a dump directory and to an `/audit-export` file, and `allowAfterRetirement` is the matching `verifyDump` and `verifyDumpStreaming` option.
- **Checkpoints and the read log are held to their signing key's window.** A vault checkpoint, read-log leaf or read-log tree head written outside the signed window of the key that signed it now fails, where a dump holding one used to verify clean. The check runs after the signature verifies and uses the time the item was written. New codes: `CHECKPOINT_KEY_NOT_YET_ACTIVE` and `CHECKPOINT_KEY_EXPIRED` (vault checkpoint), `TENANT_READ_KEY_NOT_YET_ACTIVE` and `TENANT_READ_KEY_EXPIRED` (leaf), `TENANT_CHECKPOINT_KEY_NOT_YET_ACTIVE` and `TENANT_CHECKPOINT_KEY_EXPIRED` (tree head). An item written exactly at the retirement passes. With `--trust-anchor` the window is the one the key's signed statements give; without it, the one the dump's key list gives.
- **Checkpoints, leaves and tree heads covered by a `--distrusted-key` entry are set aside.** After a leaked-key response, everything the old key signed before a trusted key retired it is now listed and never counted as evidence, as chain entries already were. Before this, those items failed as unanchored, and one planted under the leaked key raised `CHECKPOINT_ROW_MISSING`, a root mismatch or a fork on an intact chain or log. They appear as `vault.accountedCheckpoints` with `vault.accountedCheckpointCount`, and `orgAdminReads.accounted` with `orgAdminReads.accountedCount` (`AccountedReadLogEntry`). A leaf set aside keeps its index, hash and claim checks. A chain whose only checkpoints are set aside is `CHECKPOINT_ACCOUNTED_ONLY`, and more than `ACCOUNTED_CHECKPOINT_RUN_CAP` (1000) set aside above the newest one that is not is `CHECKPOINT_ACCOUNTED_RUN_EXCEEDED`.
- **A record export with its tail cut off fails.** An export with fewer entries than `exportMetadata.expectedEntries` is `CHECKPOINT_ROW_MISSING`, and fewer than `exportMetadata.totalEntries` is `CHAIN_POSITION_GAP`. Both exit `1`. The text report has an `entry count` line saying which count the chain was held to, and the JSON carries `entryCount` (`expectedEntries`, `statedEntries`). An export that verified on 2.1.0 with its tail removed now fails.
- **Dump reports count the chains a checkpoint holds the length of.** `vault.checkpointedChainCount` is how many of the `recordCount` chains were compared with at least one checkpoint (printed as `checkpointed` in the text report). A chain cut below a checkpoint fails `CHECKPOINT_ROW_MISSING`; the length of a chain with no checkpoint yet is the dump's own, and the report now says how many chains that is.

### Changed

- A sealed federation message is placed in its key's window with 300 seconds allowed at each edge.
- `cborg` is pinned at 7.0.0.

### Fixed

- **A run given a `--trust-anchor` that did not anchor no longer exits `0`.** A forged export or dump that carries its own keys verifies against them and ends `unanchored`. With a pin supplied, that now exits `3` (a new, documented code meaning nothing failed but the pin was not met), so a gate that checks the exit status cannot read it as a pass. A run with no `--trust-anchor` that ends `unanchored` still exits `0`.
- **A dump whose `chain_key` differs from its `record_id` is walked chain by chain.** Chains were opened by `chain_key` but closed by `record_id`, so every chain stayed open until the end and a chain that reappeared after another was not refused. Each chain now closes when the next row belongs to a different `chain_key`, which restores the one-chain-at-a-time memory bound and the contiguity refusal.
- **The text report on an `?evidence=true` export no longer calls the inlined evidence a display projection.** Evidence bodies are checked against the hash their entry signs; the note now leaves `evidence` out of the projections and points at the `evidence bodies` line.

## [2.1.0] - 2026-11-05

### Added

- **`--federation-key-history <file>`**: a peer's `GET /.well-known/agledger-federation-keys.json`, given beside the `--federation-key` you hold for its hub. Entries sealed before the peer changed its federation key verify under the key the history links to yours. Each message is placed by its signed `wire.timestamp`, not the entry's unsigned `createdAt`. The peer-message line reports `after-retirement=N` for messages signed under a key the peer had already retired. A hub may be named twice with `--federation-key`, to pin a key no succession links or one the history does not list. Built on `@agledger/verify-core` 2.1.0.
- **Inlined evidence is checked.** On an `/audit-export` taken with `?evidence=true`, each completion's evidence body and each dispute's filed payload is hashed (SHA-256 over RFC 8785) and compared with the `evidenceHash` or `payloadHash` its entry signs. An edited body fails `CHAIN_EVIDENCE_BINDING_MISMATCH` (exit 1) where it used to pass. The export report gains an `evidence bodies` line, which also says when an export carries no bodies, and the JSON report gains `evidenceBinding: { present, verified, clientHashed, failed }`. An encrypted-mode completion counts as client-hashed.
- **`--version` (`-V`)** prints `agledger-verify <version> (@agledger/verify-core <version>)` and exits 0, so an audit record can name the verifier that produced it. It was an unknown flag (usage text, exit 2).
- **`--federation-key <hubId>=<key>`, and `federationKeys` on `verifyDump` and `verifyDumpStreaming`.** A receiving Server seals each peer message as the peer signed it. Every sealed message is held to its body hash and its entry on every run; one from a hub whose federation key you give is also re-verified under that key, which proves what the peer asserted from this Server's dump or export alone. A bad value is a could-not-verify before anything is read, and a sealed message that does not hold fails `CHAIN_FEDERATION_WIRE_INVALID`. Reports carry `federationWire: { present, verified, failed }` under `vault` and on an export result, and the text report has a `peer msgs` / `peer messages` line that distinguishes a key that did not match from a hub given no key.

### Fixed

- On a failed run, the `agent sigs` / `agent signatures` line said its counts stopped at the first break in each chain. The walk reads every entry past a break; the counts cover the entries that passed every other check, and the line now says that.

## [2.0.0] - 2026-10-05

This release targets AGLedger API 2.0 and reads nothing older. It is built on `@agledger/verify-core` 2.0.0.

### Breaking

- **A run without `--trust-anchor` passes flagged, never as trusted.** Reports carry a `verdict`: `trusted` (clean, every signing key anchored to a pin), `unanchored` (clean, no pin given) or `failed`. An unanchored pass keeps `ok: true` and exit `0`, and says so everywhere: the text headline is `[VERIFIED, NOT ANCHORED]` with lines explaining that it is not a trusted verdict and how to get a pin from the operator (a trusted pass is `[PASS]`, a failure `[FAIL]`). The JSON carries `verdict: "unanchored"` and `keyTrust.status: "no_anchor"`. A gate that needs a trusted verdict reads `verdict` or passes `--trust-anchor`.
- **The org_admin_reads tree is RFC 9162.** Each leaf hash is recomputed as hex(sha256(0x00 || cose_sign1)) and each tree head's root as the RFC 9162 root, the construction API 2.0 writes. A dump from an older Server fails `TENANT_READ_LEAF_HASH_MISMATCH` on every leaf. The re-exports `merkleRoot` and `verifyInclusion` are removed; `orgReadLeafHash`, `orgReadMerkleRoot` and `verifyOrgReadInclusion` replace them.
- **A dump directory must contain `vault_key_statements.ndjson`**, which every API 2.0 dump writes. Without it the CLI exits `2`. `Dump` and `DumpFiles` gain `keyStatements`.
- **`--require-out-of-band-keys` is now `--require-supplied-keys`.** A key fetched from the Server comes from the same store an attacker would alter, so "out of band" promised independence it never gave. The old flag is refused with a message naming the new one. The export report's `key provenance` reads `supplied=` where it read `out-of-band=`, and the `OutOfBandKeyEntry` re-export is `SuppliedKeyEntry`.
- **`verifyVaultChains` and `verifyOrgAdminReadsChains` take the result of `walkDumpKeys`** in place of the raw signing-key rows, and `assembleReport` takes it as a third argument, so both passes grade against one verdict on each key. `VerifyReport` gains `verdict` and `keyTrust`; `ok` is false only for the `failed` verdict. `vault.optionalChecks` gains `key_anchoring`.
- `FailureCode` is now verify-core's `FailureCode`, which carries the read-log and key codes this package used to add itself.

### Added

- **Key anchoring on the dump path.** `--trust-anchor sha256:<hex>` (repeatable) and `trustAnchors` in `VerifyDumpOptions` pin vault keys held out of band. The dump's key statements are walked in write order and every row a vault key signs is graded against the result, using the Server's codes: `CHAIN_SIGNING_KEY_UNANCHORED` (chain entry), `CHECKPOINT_KEY_UNANCHORED` (vault checkpoint), `TENANT_READ_KEY_UNANCHORED` (read-log leaf), `TENANT_CHECKPOINT_KEY_UNANCHORED` (tree head). An anchored key is held to the window its statements sign. A key reached only through a statement this host cannot compute is `undecided`, and what it signed is `CHAIN_UNSUPPORTED_ALGORITHM`. Findings about the statements (`KEY_STATEMENT_INVALID`, `KEY_CLOSURE_INVALID`, `CHAIN_KEY_WINDOW_DRIFT`) fail the dump and are listed under `key anchoring` in text and in `keyTrust.findings` in JSON.
- **`--distrusted-key` and `distrustedKeys`**, matching the operator's `VAULT_DISTRUSTED_KEYS` (`sha256:<hex>`, optionally `@<RFC 3339 instant>`), given once per key. What such a key stored from that instant on, or with no instant from the retirement a trusted key signed for it, counts for nothing. Given without a pin it is refused (exit `2`, or `TypeError` from the library), as is a pinned key distrusted with no instant. A pin beside a dated entry for the same key (`sha256:<hex>@<instant>`) is accepted: the pin vouches for what the key stored before the instant. `verifyDump` and `verifyDumpStreaming` throw `TypeError` on an option they do not read, so a misspelt one cannot switch a check off, and `verifyDumpStreaming` refuses a malformed anchor or distrusted key before it reads the directory. `--distrusted-keys` is refused with a message naming `--distrusted-key`.
- **What a distrusted key signed before a trusted key retired it is accounted for on a dump, not failed.** A chain entry the key signed outside its trust is listed with the code `CHAIN_SIGNED_BY_DISTRUSTED_KEY` in `vault.accounted` (capped at `MAX_REPORTED_FAILURES`) with the total in `vault.accountedCount`; a key statement it signed is listed in `keyTrust.accounted`. The text report lists both as `accounted for`. They are not verified, do not count toward `vault.signedEntries`, and fail nothing, so a dump whose only such items are accounted for passes. The JSON keys match the Python `agledger-verify`. `AccountedEntry`, `AccountedEntryCode`, `ACCOUNTED_ENTRY_CODE`, `DistrustSpan` and `KeyTrustNote` are re-exported from verify-core. On an export file such entries and statements still fail.
- **An export's `distrustedFrom` is read.** Where the Server's `VAULT_DISTRUSTED_KEYS` entry cut a key's retirement and the run was not given the same `--distrusted-key`, the `CHAIN_KEY_WINDOW_DRIFT` (or `KEY_CLOSURE_INVALID`) finding names the entry to confirm with the Server's operator instead of reading as a rewritten value. It also says when the entry you gave carries another instant, and an earlier given instant is a note. Verdict and exit code are unchanged.
- **The CLI's findings, notes and failures name its flags.** Where verify-core's wording names an option, the text and JSON reports say `--distrusted-key`, `--trust-anchor`, `--require-key-id` and `--require-supplied-keys`. The library's results keep verify-core's option names.
- Both flags apply to an `/audit-export` file too, and the export JSON carries `verdict` beside verify-core's result.
- **The signed claims are checked against their rows.** A vault checkpoint whose envelope does not decode as a claim, or whose signed position, tip hash, record subject or key id differs from its row, fails `CHECKPOINT_CLAIM_MISMATCH`. A read-log leaf whose signed position, previous-leaf hash, record id or record subject differs from its row fails `TENANT_READ_CLAIM_MISMATCH`. A read-log tree head whose signed size, root, count or key id differs fails `TENANT_CHECKPOINT_CLAIM_MISMATCH`. Before this, a rewritten value beside an intact envelope passed. `cborg` is now a runtime dependency, to read the claim as the Server does.
- **With a pin, the instant the install began signing is held to the signed activations too.** The unsigned-row rule dates the install's first signature from the earliest activation time the dump's signing keys list, which is unsigned. With `--trust-anchor`, the activations the anchored keys' statements sign count as well and the earliest stands, so removing the dump's unsigned activation time or moving it later no longer switches the rule off.
- **A pin over a dump with nothing signed by a key it anchors is not a trusted pass.** When `--trust-anchor` was walked but no vault entry verified under an anchored key (for example a dump of history written before the install began signing), `keyTrust.status` is `no_anchored_signature` and the verdict `unanchored`: exit `3`, headline `[VERIFIED, NOT ANCHORED]`. `vault.signedEntries` counts the entries whose signature verified, and `vault.optionalChecks.key_anchoring` is `not_checked` when a pin was given but no entry reached the anchoring check.
- **A vault row with no readable time fails closed.** An entry with a null, missing or unparseable write time fails `CHAIN_MALFORMED_ENTRY` wherever its key's window or the start of signing needs one. Before, nulling every write time let entries signed by a distrusted key after its cutoff pass. An unsigned vault checkpoint, read-log leaf or tree head with no readable time once signing began fails its unsigned code.
- **Malformed rows are failure codes, not exceptions.** A null or dropped `payload` fails `CHAIN_PAYLOAD_BINDING_MISMATCH`; a key row with no `public_key` is no key, so what names it fails `CHAIN_SIGNATURE_MISSING_KEY`; a retyped `chain_key`, a null checkpoint or read-log `record_id` and a null tree-head `root_hash` no longer throw; a `tree_size` that is not a safe integer fails `TENANT_CHECKPOINT_LEAF_COUNT_MISMATCH`; rows whose `chain_position` or `leaf_index` is not a safe integer sort last and fail their position or index check.
- A vault checkpoint, read-log leaf or tree head whose `cose_sign1` is null now fails `CHECKPOINT_CLAIM_MISMATCH`, `TENANT_READ_LEAF_HASH_MISMATCH` or `TENANT_CHECKPOINT_CLAIM_MISMATCH`. It used to throw, which the CLI reported as exit `2` (could not verify) rather than as a failed verdict.
- A malformed pin or distrusted key, a distrusted key named twice, and a target that does not exist are exit `2`: no verdict was reached. A key statement row with no readable write time is `KEY_STATEMENT_INVALID` (exit `1`). The flags, these refusals, their messages and the headlines are the same in the Python `agledger-verify` and in `agledger verify`.
- New exports: `walkDumpKeys` and `MAX_REPORTED_FAILURES` (the cap on each report section's failure list); the types `DumpKeyTrust`, `KeyTrustOptions`, `VaultChainOptions`, `KeyStatementDump` and `Verdict`; and re-exports of `computeKeyTrust`, `applyKeyTrust`, `parseTrustAnchors`, `parseDistrustedKeys`, `spkiSha256` and the `KeyTrust`, `KeyTrustReport`, `KeyTrustStatus` and `DistrustedKey` types. `KeyTrustStatus` is `walked`, `no_anchor` or `no_anchored_signature`; only `walked` on a clean run gives the `trusted` verdict.
- **A full dump re-verifies sealed agent signatures without `--agent-keys`.** The dump verifier takes the cert public keys the platform-ops chain signs, from a chain it has verified clean and only from entries whose vault signature checked. They are used beside any `--agent-keys` / `agentKeys`, and the dump report counts them as `vault.certKeysFromChain`. The `agent sigs` line says when the keys came from the dump.

### Fixed

- **An unsigned row written once the install signs is a break.** The instant the install began signing is the earliest activation time among the dump's signing keys, retired keys included. An unsigned chain entry written at or after it, or after a signed entry in the same chain, fails `CHAIN_ENTRY_UNSIGNED`. An unsigned vault checkpoint written at or after it fails `CHECKPOINT_UNSIGNED`. On the cross-party read log, a leaf with the unsigned sentinel key id `0000000000000000` fails `TENANT_READ_LEAF_UNSIGNED` when read at or after that instant or after a signed leaf in the same org's log, and an unsigned tree head written at or after it fails `TENANT_CHECKPOINT_UNSIGNED`. An existing tamper finding keeps its own code. Unsigned rows from before the first key activation stay reduced coverage, so an install that never registered a key still verifies. Before this, an unsigned entry or checkpoint anywhere was only reduced coverage.
- **A read-log leaf's signature is verified.** A leaf that names a real key now has its COSE_Sign1 signature checked under that key: one that does not verify, carries an all-zero signature, or does not decode fails `TENANT_READ_SIGNATURE_INVALID`, and a key id the key registry does not hold fails `CHAIN_SIGNATURE_MISSING_KEY`. Only the leaf hash and index were checked before, so a restamped leaf passed.
- **A chain-entry failure names the chain it is on.** A failure on a schema chain now reads `Chain schema:<orgId> pos N` instead of presenting the chain key as a record id, and a failure on a per-record chain reads `Record <id> pos N`.
- **An all-zero signature on a chain entry that names a signing key fails `CHAIN_SIGNATURE_INVALID`** rather than being graded unsigned.
- **The README wrongly said neither a dump nor an export carries cert public keys.** A dump not scoped to one org does: each `EPHEMERAL_CERT_ISSUED` entry on the platform-ops chain signs its cert's `publicKeyJwk` (API 1.8.0 on). An org-scoped dump leaves that chain out, a per-record `/audit-export` does not include it, and a cert issued before 1.8.0 carries only its thumbprint. The README and `--help` now say so.

### Changed

- The export path walks key statements in write order too, so an export and a dump of the same Server are walked alike. The write times decide only the order; they are not signed, so a key statement signed by a key in `distrustedKeys` counts for nothing whatever time it carries. A statement that counts for nothing only because its signer is distrusted, dated before the cutoff by the export's own unsigned write time, is a `keyTrust.notes` entry rather than a finding, so an honest rotation away from a key distrusted afterward still passes pinned on its successor. The text report lists each note under `key anchoring`.
- Requires `@agledger/verify-core` 2.0.0.
- The conformance corpus is regenerated from API 2.0.0 and adds the key-statement, unsigned-row and RFC 9162 vectors. Pinned on the Server's current key, the three registry column-edit vectors (`chain-key-expired`, `chain-key-not-yet-active`, `valid-rotation-boundary`) read as `KEY_CLOSURE_INVALID` or `CHAIN_KEY_WINDOW_DRIFT` rather than the window codes their manifest names, since a pinned walk holds entries to the signed window; unpinned they give their manifest verdicts.
- The agent-signature line reads `no key for their cert` where it read `no key supplied for their cert`, since a key can now come from the dump.
- On a failed run the agent-signature line says its counts stop at the first break in each chain; it used to say `none on the chain` when signatures sat beyond the break.
- An `/audit-export` file verify-core refuses as malformed is reported with the file's name, and the note on the `--keys` file's shape is added only when `--keys` was given and is what was refused.
- A vault row with no `cose_sign1` is described as carrying no signed envelope (a Server that predates it, or a removed column) rather than as a "pre-2.0 dump shape".

## [1.6.0] - 2026-09-21

### Added

- **`--agent-keys <file>`** re-verifies, offline, the agent signatures sealed in chain entries, on a dump directory and on an `/audit-export` file. The file holds the Ed25519 public keys of agent ephemeral certs as one JWK, a list of JWKs, or a `{keys: [...]}` JWK Set (an entry may wrap its key as `{publicKeyJwk: {...}}`), the same shapes `agledger verify --agent-keys` takes. An entry whose sealed cert thumbprint names one of the keys has its agent signature checked, and one that does not verify fails `CHAIN_AGENT_SIGNATURE_INVALID`. A file with no keys, or with anything that is not an Ed25519 JWK, exits 2 with a message saying what is wrong.
- Both reports say whether the check ran and count agent signatures present and verified: an `agent sigs` / `agent signatures` line in text, and `optionalChecks.agent_signature` plus `agentSignatures` in JSON (on the dump report, under `vault`). Without `--agent-keys` the check is reported as not run and no verdict changes.
- The dump report's `vault` gains `optionalChecks`, saying which input-gated checks (payload binding, OIDC actor, key validity window, agent signature) ran on at least one chain.
- `verifyDumpStreaming`, `verifyDump` and `verifyVaultChains` take an options argument with `agentKeys`. `buildAgentKeyRegistry` and the `AgentPublicKeyJwk`, `AgentKeyRegistry`, `OptionalCheck`, `CheckApplicability` and `VerifyDumpOptions` types are exported.

### Fixed

- **Actor attribution is verified, not displayed on trust.** An export's `actorId`, `actorOwnerId` and `actorRole` are signature-covered, but nothing compared them with the signed values, so an export or dump row could be re-attributed to another actor and still verify. They are now cross-checked per entry, on a dump directory and on an `/audit-export` file, and a divergence fails the new `CHAIN_ACTOR_ATTRIBUTION_MISMATCH`. The text report's `note` line now states whether attribution was cross-checked and agrees, or that the export carried no signed actor claim to check it against.
- Row copies of `on_behalf_of` or `traceparent` are held to the value the entry signed: a rewritten or added copy now fails `CHAIN_PAYLOAD_BINDING_MISMATCH` instead of verifying, in a dump and in an export.
- Conformance corpus regenerated against API 1.8.0 (export slice 23 to 32 vectors, dump slice 12 to 18), including vectors for actor attribution and agent signatures.

### Changed

- Requires `@agledger/verify-core` 1.5.0.
- `LICENSE` is updated: it states that AGLedger LLC does not receive, inspect or use the data you process through your deployment and collects no product usage information from it, names AGLedger and Settlement Signal as trademarks of AGLedger LLC, and refers to issued or pending U.S. patents.

## [1.5.3] - 2026-09-10

### Changed

- `LICENSE` section 6 names the ciphers this package line ships: Ed25519 (EdDSA), ECDSA P-256 with SHA-256, HMAC-SHA-256, AES-256-GCM, HKDF-SHA-256 and SHA-256. No code changed.

## [1.5.2] - 2026-08-30

Documentation only. Verification behaviour is identical to 1.5.1.

### Added

- The README documents how to install the package.

## [1.5.1] - 2026-08-07

### Fixed

- **A FIPS-locked host no longer reports an intact Ed25519 dump as tamper.** The FIPS provider carries no EdDSA, and the refusal to compute the signature was reported as `CHAIN_SIGNATURE_INVALID` on every entry. It is now `CHAIN_UNSUPPORTED_ALGORITHM`, naming the provider as the cause and pointing at an unrestricted host. Still `[FAIL]` and exit 1, because an unverified chain is not a verified one, but no longer grounds for a tamper investigation.
- Checkpoint failure messages no longer say a signature failed when it was never checked. They now read "signature could NOT BE CHECKED" plus the reason and the remedy.

### Packaging

- Source maps are no longer published; they pointed at sources the package does not ship.

## [1.5.0] - 2026-08-07

### Fixed

- **A healthy schema chain no longer fails the whole dump.** A stock Compose install, untouched, returned `[FAIL]` and exit 1 with `CHECKPOINT_ROW_MISSING`, a tamper alarm for any audit gate wired to the exit code. Checkpoints are now grouped by `chain_key`, falling back to `record_id` so older dumps verify as before.
- Failures name a schema chain as `Chain schema:<orgId>` instead of `RecordRow <uuid>`.

### Changed

- `CHAIN_KEY_NOT_YET_ACTIVE` is reported for an entry written before its signing key's activation; `CHAIN_KEY_EXPIRED` now means the retirement side only. Previously both directions reported "expired". Verdicts are unchanged. (Via `@agledger/verify-core` 1.3.0.)

## [1.4.0] - 2026-08-05

### Added

- **ES256 verification** across every surface this package checks (chain walk, vault checkpoints, org-admin-reads signed tree heads), chosen from the trusted key rather than the envelope header. Algorithms beyond this build (ES384, ES512, ES256K) still fail closed as `CHAIN_UNSUPPORTED_ALGORITHM`. Ed25519 chains verify exactly as in 1.3.1. (Via `@agledger/verify-core` 1.2.0.)

### Changed

- Conformance corpus regenerated against API 1.3.4 with ES256 vectors, including `es256-header-alg-mismatch` (a valid ES256 signature under an EdDSA header reads as `CHAIN_ALG_MISMATCH`).

## [1.3.1] - 2026-08-05

### Fixed

- **An empty-string `signing_key_id` is no longer treated as unsigned.** Only null or missing means unsigned, so a tampered empty value now fails `CHAIN_SIGNATURE_MISSING_KEY` instead of skipping the signature check. Applies to the chain walk and to both checkpoint kinds.

## [1.3.0] - 2026-08-05

Legitimate Ed25519 dumps verify identically; what changes is fail-closed classification of tampered and non-Ed25519 inputs.

### Changed

- Takes `@agledger/verify-core` `^1.1.0`, inheriting key-bound algorithm dispatch, the tamper-class `CHAIN_ALG_MISMATCH`, the fail-closed `CHAIN_UNSUPPORTED_ALGORITHM`, signed-kid binding (`CHAIN_SIGNING_KEY_DRIFT`) and rejection of untagged COSE_Sign1.
- **Checkpoint signature checks fail closed on every non-ok outcome.** Vault checkpoints and org-admin-reads signed tree heads previously passed an all-zero signature on a checkpoint that claims a signing key. Any non-ok outcome now fails with `CHECKPOINT_SIGNATURE_INVALID` / `TENANT_CHECKPOINT_SIGNATURE_INVALID`, or `CHAIN_UNSUPPORTED_ALGORITHM` when the key's algorithm is beyond this build.
- The signing-key registry's declared algorithm is cross-checked against the key material; a registry row that misdescribes its own key fails `CHAIN_ALG_MISMATCH`.
- Conformance corpus refreshed from Server 1.3.4, with new `chain-signing-key-drift` and `chain-alg-registry-lie` dump vectors.

## [1.2.0] - 2026-08-01

A full-installation dump larger than about 512 MB could not be verified: it died in about a second with `Cannot create a string longer than 0x1fffffe8 characters`.

### Fixed

- **Files are read in chunks and verified one chain at a time**, so file size is bounded by disk and peak memory is the largest single chain rather than the whole vault.
- A chain that reappears after its group closed is reported as `UNSUPPORTED_FORMAT` with an instruction to re-export, instead of silently verifying a partial chain as clean.

### Changed

- **Exit codes split.** `1` is verification FAILED, `2` is could NOT verify. Both were `1`, so a missing or oversized dump looked like a broken chain to any gate wired to "nonzero means tampering". `--report-format json` now emits JSON for input errors too. A script asserting `exitCode === 1` on a bad path will now see `2`.
- **Failure lists are capped**, with the true total in a new `failureCount` field on `VaultChainsReport` and `TenantAdminReadsReport`. A systemic fault yields one failure per entry; one 621 MB dump produced 462,002 failures and 51 MB of stdout, and now produces a 114 KB report. A consumer reading `failures.length` as the count under-reports above 1000 failures.
- `verifyDumpStreaming` is the preferred entry point and is what the CLI uses. `loadDump` and `verifyDump` keep their signatures and produce the same report. No dump-format change.

## [1.1.1] - 2026-07-16

Docs and tooling. No verification or wire-format change.

### Fixed

- README and package links point at the public source repo.

## [1.1.0] - 2026-07-06

**Security:** the CLI now verifies against keys you supply out of band, as the README prescribes. Without them, an export re-signed with a substituted key could pass; upgrade and pass your keys.

### Added

- **`--keys <file>`**: supply out-of-band public keys for an `/audit-export` file. Accepts a `{keyId: SPKI-DER-base64}` map, a `[{keyId, publicKey, ...}]` list, or the raw `GET /v1/verification-keys` response (the `.data` is unwrapped automatically, as in `agledger verify --keys`). Merged over any keys embedded in the export.
- **`--require-out-of-band-keys`**: refuse keys embedded in the export; a substituted key now fails closed (`CHAIN_KEY_POLICY_VIOLATION` at the swapped entry).
- **`--require-key-id <id>`**: reject an otherwise-valid export signed by a retired or unexpected key.
- The text report prints an explicit WARNING when a PASS was earned only against keys embedded in the export itself.
- README: "Independent verification of an export" section with the fetch-keys-out-of-band workflow.

### Notes

- The key-policy flags apply to `/audit-export` files only; a dump directory carries its own signed key history and rejects them with a usage error.
- Without `--keys`, embedded keys are still trusted, and all previously passing and failing vectors keep their results.

## [1.0.2] - 2026-06-29

### Changed

- Documentation wording.

## [1.0.1] - 2026-06-22

### Added

- **Unsigned-projection warning on the audit-export verdict.** When an export lists unsigned projection fields (`verificationGuide.unsignedFields`), a green `[PASS]` now prints a non-fatal `note:` naming them and stating that attribution is the signed `actorOwnerId`/`actorId` UUID, not these labels. `--report-format json` carries the `unsignedProjectionFields` array. No change to chain verification or exit codes.

### Changed

- Requires `@agledger/verify-core` `^1.0.1`.

## [1.0.0] - 2026-06-20

### Changed

- **1.0.0 GA**, aligned with AGLedger API v1.0.0. Requires `@agledger/verify-core` `^1.0.0`. No verifier-logic or CLI changes from 0.1.6; dump-verification behavior and exit codes are unchanged.

Releases before 1.0.0 are listed on npm (https://www.npmjs.com/package/@agledger/verify?activeTab=versions).
