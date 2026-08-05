# @agledger/verify

Standalone offline verifier for a **full AGLedger installation dump**: the
per-record `audit_vault` hash chain, the vault checkpoints, and the
`org_admin_reads` Merkle log, all read from a static NDJSON dump. No engine, no
database, no network.

Built on [`@agledger/verify-core`](https://www.npmjs.com/package/@agledger/verify-core): the per-record (and per-org
schema-event) hash-chain walk is the same body of logic the SDK `/verify`
subpath, the CLI, and the MCP server all run. This package adds the
dump-structural passes the core does not model (checkpoint cross-check, the
org-admin-reads STH + fork detection) and the full-vault loader.

## Why

The engine signs every state transition (Ed25519 by default, ES256 behind
the server-side opt-in). A customer's auditor
needs an independent verifier that does not trust the engine. If the engine
were compromised, an in-engine "everything is fine" report would be worth
nothing. This package is that escape hatch: it lives outside the engine and
checks a dump the operator produces with the engine's `vault:dump` exporter.
For a fully independent audit, supply
the vault verification keys out of band rather than trusting any keys carried in
the dump.

## CLI

```bash
agledger-verify <target> [--report-format text|json] [--keys <file>]
                [--require-key-id <id>] [--require-out-of-band-keys]
```

`<target>` is auto-detected:

- a **directory** is treated as a full-vault NDJSON dump and verified with the
  streaming dump verifier (`verifyDumpStreaming`).
- a **file** is parsed as JSON; if it carries `exportMetadata` + `entries` it is
  a single `/audit-export` document and verified with the per-record export
  verifier (`verifyAuditExport` from `@agledger/verify-core`).

`--report-format json` emits a single JSON object (not NDJSON), including for
input errors, so a machine consumer always gets something parseable.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Verified. No failures. |
| `1` | Verification FAILED. The chain or log does not hold up. |
| `2` | Could NOT verify. The input was missing, unreadable, or malformed; no verdict was reached. |

`1` and `2` mean opposite things, so treat only `1` as evidence of tampering.
An audit gate wired to "nonzero means the chain is broken" will otherwise raise
a tamper alarm over a mistyped path.

### Vault size

`audit_vault.ndjson` is streamed and verified one chain at a time, so a dump is
bounded by disk rather than by memory. Peak memory is the largest single chain,
not the vault. There is no size ceiling to work around.

Failure lists are capped at `MAX_REPORTED_FAILURES` entries per section, with
the true total in `failureCount` and a `... and N more not shown` line in the
text report. A systemic problem on a large vault produces one failure per
entry, and burying the finding under a million identical lines helps nobody.

### Independent verification of an export

Without `--keys`, an `/audit-export` file is verified against the signing keys
carried **inside that same export**. That proves internal consistency, not
independence: an attacker who fully re-signs a chain with their own key and
embeds it also passes, and the text report says so
(`key provenance: out-of-band=0` plus an explicit warning line). For the
independent audit this README's "Why" section describes, fetch the keys
separately and require them:

```bash
# Save the engine's verification keys through a channel you trust
# (the raw response envelope is accepted as-is; .data is unwrapped).
curl -s https://ledger.example.com/v1/verification-keys > keys.json

agledger-verify export.json --keys keys.json --require-out-of-band-keys
```

`--keys` accepts a `{keyId: SPKI-DER-base64}` map, a
`[{keyId, publicKey, ...}]` list, or the raw `GET /v1/verification-keys`
response envelope. `--require-key-id <id>` additionally rejects an
otherwise-valid export signed by a retired or unexpected key. The key-policy
flags apply to `/audit-export` files only; a dump directory carries its own
signed key history (`vault_signing_keys.ndjson`) and rejects them.

## Library

```ts
import { verifyDumpStreaming } from '@agledger/verify';

const report = verifyDumpStreaming('/path/to/dump');
if (!report.ok) {
  console.error(JSON.stringify(report, null, 2));
  process.exit(1);
}
```

`verifyDumpStreaming` is the one to reach for: it streams `audit_vault.ndjson`
instead of materializing it. `loadDump` + `verifyDump` still exist and produce
the same report, but they hold every row, so keep them for dumps small enough
to fit in heap.

The shared core's per-record export path and the low-level primitives
(`verifyAuditExport`, `verifyChain`, `merkleRoot`, `verifyCoseSign1`, …) are
re-exported so a caller need not add a second dependency.

## What is verified

- **`audit_vault` per-record chain** (via `verify-core`): chain_position
  monotonicity, payload_hash = sha256(cose_sign1), previous_hash linkage, the
  signed COSE protected-header chain-claim cross-check, the envelope
  signature (Ed25519 or ES256, dispatched from the trusted key material),
  plus the dump-only input-gated checks: binding-integrity
  (`CHAIN_PAYLOAD_BINDING_MISMATCH`), OIDC-actor cross-check
  (`CHAIN_OIDC_ACTOR_MISMATCH`), and temporal key-validity
  (`CHAIN_KEY_EXPIRED`).
- **Vault checkpoints**: the anchor row matches the live entry at its position
  and its signature verifies. A checkpoint without a matching `audit_vault` row
  is evidence of out-of-band TRUNCATE/DELETE (`CHECKPOINT_ROW_MISSING`).
- **`org_admin_reads` chain**: leaf_hash matches sha256(cose_sign1), leaf_index
  gap-free per org.
- **STH (signed tree head) checkpoints**: recomputed Merkle root over the first
  `tree_size` leaves matches the signed `root_hash`; signature verifies.
- **Engine-fork detection**: two checkpoints at the same `tree_size` carrying
  different `root_hash` is `TENANT_CHECKPOINT_FORK`.

## Fail-closed posture

- An **empty or truncated vault** (zero entries) does NOT verify clean. It
  reports `CHAIN_EMPTY`.
- A vault row lacking `cose_sign1` is a **pre-2.0 dump shape** and is rejected
  with `UNSUPPORTED_FORMAT` rather than parsed best-effort.

## What is NOT verified

- **Witness cosignatures** are stored verbatim and reported (checkpoint id,
  witness key id), but their signature is not checked. The witness key
  algorithm is customer-chosen and out of band.

## Wire format

See `src/types.ts`. One JSON object per line:

| File | Description |
|---|---|
| `audit_vault.ndjson` | Per-record (and per-org schema-event) hash-chain entries. |
| `vault_checkpoints.ndjson` | Periodic signed checkpoints over the chain. |
| `vault_signing_keys.ndjson` | Public-key registry with rotation windows. |
| `org_admin_reads.ndjson` | Admin cross-party read log. |
| `org_admin_reads_checkpoints.ndjson` | Signed-tree-head envelopes over the read log. |

All timestamps are ISO-8601. Bigints are serialized as JS numbers.

## Conformance corpus

The DUMP-kind vectors under `testdata/conformance/dump/` (manifest:
`testdata/conformance/manifest-dump.json`) and the EXPORT-kind vectors under
`testdata/conformance/export/` (manifest: `testdata/conformance/manifest-export.json`)
are the anti-drift seam shared with the independent Python verifier. They are
**real engine output**, not synthesized here, so the two verifiers are held to
the same wire format and agree verdict-for-verdict.
