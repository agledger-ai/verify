# AGLedger verifier conformance corpus — contract

This directory is the **anti-drift seam** for AGLedger's offline verifiers. It
holds known-good and known-tampered fixtures that ARE real engine output, each
paired with an expected verdict + canonical failure code. Every verifier surface
(TS `@agledger/verify-core`, the `@agledger/verify` dump verifier, and the
independent Python `agledger.verify`) runs this corpus in CI. A change to the
engine wire format bumps the corpus; the verifiers update in lockstep.

**`agledger-api` owns generation** (it owns the contract: wire format + dump
producer + corpus). The fixtures here are produced by `agledger-api`'s
`scripts/generate-conformance-corpus.ts` — it boots the real engine, captures
byte-faithful `/audit-export` JSON and `dump-vault` NDJSON, then applies
controlled tamper transforms. Regenerate (on a wire-format change) from an
`agledger-api` checkout with a local Postgres up: `pnpm generate:corpus`. Each
manifest carries a `provenance` block recording the producing api SHA + version.
Do NOT hand-edit fixtures — regenerate.

Lesson encoded here (F-682): fixtures MUST mirror the real export/dump shape
exactly — never a bilingual superset (e.g. carrying both `position` and
`chainPosition`). A superset masks field-name drift.

## Layout

```
testdata/conformance/
  SPEC.md                 (this file)
  export/                 export-kind fixtures (one /audit-export JSON each)
    *.json
    keys-oob.json         out-of-band key map {keyId: spkiBase64}
    keys-attacker.json    attacker-controlled key map
  dump/                   dump-kind fixtures (one 5-file NDJSON dir each)
    <name>/audit_vault.ndjson, vault_checkpoints.ndjson, ...
  manifest-export.json    export vectors
  manifest-dump.json      dump vectors
```

Two manifests (by input kind) because export vectors are verified by
`verifyAuditExport` and dump vectors by the dump verifier — different
entrypoints. Together they are one corpus.

## Manifest schema (both files share it)

```jsonc
{
  "description": "...",
  "formatVersion": "2.0",
  "canonicalization": "RFC8949-CDE",
  "generatedAt": "<ISO-8601>",
  "vectors": [
    {
      "file": "export/valid.json",        // export: a JSON file; dump: a directory
      "kind": "export",                    // "export" | "dump"
      "expect": "pass",                    // "pass" | "fail"
      "failureCode": "CHAIN_HASH_MISMATCH",// REQUIRED iff expect=="fail"; a canonical FailureCode
      "brokenAt": 2,                        // optional (export): expected first-failing position
      "options": {                          // optional verify options for this vector
        "keysFile": "export/keys-oob.json", // out-of-band publicKeys to load
        "requireKeyId": "vault-key-1",
        "requireOutOfBandKeys": true
      },
      "expectSignatureCoverage": { "signed": 0, "unsigned": 3, "skipped": 0 }, // optional assertion
      "note": "human description of what is tampered and why it must fail"
    }
  ]
}
```

A runner: load each vector of the kind it supports, run the verifier with
`options`, then assert `expect` and — on fail — that `brokenAt.code ===
failureCode` (and `brokenAt.position === brokenAt` when given), plus any
`expectSignatureCoverage`. A runner MUST fail loudly if a `pass` vector fails or
a `fail` vector passes/returns the wrong code — that is the whole point.

## Canonical FailureCode taxonomy

Defined in `packages/verify-core/src/failures.ts`. SCREAMING_SNAKE, namespaced:

- input/format: `UNSUPPORTED_FORMAT`, `CHAIN_EMPTY`
- per-record chain: `CHAIN_POSITION_GAP`, `CHAIN_GENESIS_INVALID`,
  `CHAIN_LINK_BROKEN`, `CHAIN_HASH_MISMATCH`, `CHAIN_MALFORMED_ENTRY`,
  `CHAIN_COSE_DECODE_FAILED`, `CHAIN_COSE_HEADER_MISMATCH`,
  `CHAIN_PAYLOAD_BINDING_MISMATCH`, `CHAIN_OIDC_ACTOR_MISMATCH`,
  `CHAIN_SIGNATURE_INVALID`, `CHAIN_SIGNATURE_MISSING_KEY`,
  `CHAIN_KEY_POLICY_VIOLATION`, `CHAIN_KEY_EXPIRED`
- checkpoints: `CHECKPOINT_ROW_MISSING`, `CHECKPOINT_HASH_MISMATCH`,
  `CHECKPOINT_SIGNATURE_INVALID`
- org_admin_reads: `TENANT_READ_LEAF_HASH_MISMATCH`,
  `TENANT_READ_LEAF_INDEX_GAP`, `TENANT_READ_SIGNATURE_INVALID`,
  `TENANT_CHECKPOINT_LEAF_COUNT_MISMATCH`, `TENANT_CHECKPOINT_ROOT_MISMATCH`,
  `TENANT_CHECKPOINT_SIGNATURE_INVALID`, `TENANT_CHECKPOINT_FORK`

## verify-core public API (consumed by every TS surface)

```ts
import { verifyAuditExport, verifyChain, buildKeyRegistry,
         type VerificationKey, type NormalizedEntry, type FailureCode } from '@agledger/verify-core';

// export path:
const r = verifyAuditExport(exportJson, { publicKeys?, requireKeyId?, requireOutOfBandKeys? });
// r: { valid, totalEntries, verifiedEntries, brokenAt?{position,code,detail}, entries[], recordId,
//      signatureCoverage{signed,unsigned,skipped,total}, optionalChecks{payload_binding,oidc_actor,key_temporal},
//      keyProvenance{outOfBand,embedded} }

// dump path builds NormalizedEntry[] WITH binding/oidcActor/createdAt + keys with
// activatedAt/retiredAt windows, then calls verifyChain(entries, keyRegistry, opts) per chain.
```

`NormalizedEntry` optional fields drive the input-gated checks:
`binding{recordId,entryType,payload}` -> CHAIN_PAYLOAD_BINDING_MISMATCH;
`oidcActor{iss,sub,synthesized}` -> CHAIN_OIDC_ACTOR_MISMATCH;
`createdAt` + key `activatedAt/retiredAt` -> CHAIN_KEY_EXPIRED. Absent inputs =>
the check reports `skipped_no_input` (never a silent pass).

## Required vectors (minimum)

**Export** (`manifest-export.json`): valid (multi-entry, signed); plus a matched
`fail` per code: `CHAIN_POSITION_GAP`, `CHAIN_GENESIS_INVALID`,
`CHAIN_LINK_BROKEN`, `CHAIN_HASH_MISMATCH`, `CHAIN_MALFORMED_ENTRY`,
`CHAIN_COSE_DECODE_FAILED`, `CHAIN_COSE_HEADER_MISMATCH` (valid signature but the
signed -65537 chain claim disagrees with the row columns), `CHAIN_SIGNATURE_INVALID`,
`CHAIN_SIGNATURE_MISSING_KEY`, `UNSUPPORTED_FORMAT` (one version vector + one
canonicalization vector), `CHAIN_EMPTY`. Plus policy/compound: a valid chain that
`fail`s `CHAIN_KEY_POLICY_VIOLATION` under `requireKeyId`; a key-substitution
fixture (tampered entry re-signed with the attacker key, attacker key present in
embedded set) that PASSES with no options (documents the embedded-key trust
assumption) and FAILs `CHAIN_KEY_POLICY_VIOLATION` under `requireOutOfBandKeys`;
an unsigned chain (all-zero 64-byte sig) that PASSES with
`expectSignatureCoverage {signed:0, unsigned:N}` (proves unsigned is reported as
hash-chain-only, never as cryptographically signed).

**Dump** (`manifest-dump.json`): valid; `CHAIN_EMPTY` (empty/truncated vault —
the fail-closed fix); `CHECKPOINT_ROW_MISSING`; `CHECKPOINT_HASH_MISMATCH`;
`CHAIN_PAYLOAD_BINDING_MISMATCH`; `CHAIN_OIDC_ACTOR_MISMATCH`; `CHAIN_KEY_EXPIRED`
(entry signed outside the key's activated..retired window — the retired-key
fail-open fix); `TENANT_CHECKPOINT_ROOT_MISMATCH`; `TENANT_CHECKPOINT_FORK`.
