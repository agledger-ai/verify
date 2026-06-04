# @agledger/verify

Standalone offline verifier for a **full AGLedger installation dump** — the
per-record `audit_vault` hash chain, the vault checkpoints, and the
`org_admin_reads` Merkle log — from a static NDJSON dump. No engine, no
database, no network.

Built on [`@agledger/verify-core`](../verify-core): the per-record (and per-org
schema-event) hash-chain walk is the same body of logic the SDK `/verify`
subpath, the CLI, and the MCP server all run. This package adds the
dump-structural passes the core does not model (checkpoint cross-check, the
org-admin-reads STH + fork detection) and the full-vault loader.

## Why

The engine signs every state transition with Ed25519. A customer's auditor
needs an independent verifier that does not trust the engine — if the engine
were compromised, an in-engine "everything is fine" report would be worth
nothing. This package is that escape hatch: it lives outside the engine and
checks a dump the operator produces with the engine's `vault:dump` exporter
(`scripts/dump-vault.ts` in agledger-api). For a fully independent audit, supply
the vault verification keys out of band rather than trusting any keys carried in
the dump.

## CLI

```bash
agledger-verify <target> [--report-format text|json]
```

`<target>` is auto-detected:

- a **directory** is treated as a full-vault NDJSON dump and verified with the
  dump verifier (`loadDump` + `verifyDump`).
- a **file** is parsed as JSON; if it carries `exportMetadata` + `entries` it is
  a single `/audit-export` document and verified with the per-record export
  verifier (`verifyAuditExport` from `@agledger/verify-core`).

Exits `0` on a fully verified target, nonzero on any verification failure or
input error. `--report-format json` emits a single JSON object (not NDJSON).

## Library

```ts
import { loadDump, verifyDump } from '@agledger/verify';

const dump = loadDump('/path/to/dump');
const report = verifyDump(dump);
if (!report.ok) {
  console.error(JSON.stringify(report, null, 2));
  process.exit(1);
}
```

The shared core's per-record export path and the low-level primitives
(`verifyAuditExport`, `verifyChain`, `merkleRoot`, `verifyCoseSign1`, …) are
re-exported so a caller need not add a second dependency.

## What is verified

- **`audit_vault` per-record chain** (via `verify-core`) — chain_position
  monotonicity, payload_hash = sha256(cose_sign1), previous_hash linkage, the
  signed COSE protected-header chain-claim cross-check, the Ed25519 signature,
  plus the dump-only input-gated checks: binding-integrity
  (`CHAIN_PAYLOAD_BINDING_MISMATCH`), OIDC-actor cross-check
  (`CHAIN_OIDC_ACTOR_MISMATCH`), and temporal key-validity
  (`CHAIN_KEY_EXPIRED`).
- **Vault checkpoints** — the anchor row matches the live entry at its position
  and its signature verifies. A checkpoint without a matching `audit_vault` row
  is evidence of out-of-band TRUNCATE/DELETE (`CHECKPOINT_ROW_MISSING`).
- **`org_admin_reads` chain** — leaf_hash matches sha256(cose_sign1), leaf_index
  gap-free per org.
- **STH (signed tree head) checkpoints** — recomputed Merkle root over the first
  `tree_size` leaves matches the signed `root_hash`; signature verifies.
- **Engine-fork detection** — two checkpoints at the same `tree_size` carrying
  different `root_hash` is `TENANT_CHECKPOINT_FORK`.

## Fail-closed posture

- An **empty or truncated vault** (zero entries) does NOT verify clean — it
  reports `CHAIN_EMPTY`.
- A vault row lacking `cose_sign1` is a **pre-2.0 dump shape** and is rejected
  with `UNSUPPORTED_FORMAT` rather than parsed best-effort.

## What is NOT verified

- **Witness cosignatures** are stored verbatim and reported (checkpoint id,
  witness key id), but their signature is not checked — the witness key
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
**real engine output** — produced and owned by `agledger-api`, not generated
here; there is no local generate script in this repo.

To refresh on a wire-format change, regenerate from a checkout of `agledger-api`
(with a local Postgres up) using its corpus generator, then copy the output into
this repo:

```bash
# in the agledger-api checkout
npx tsx scripts/generate-conformance-corpus.ts

# copy the regenerated corpus into this repo's testdata/conformance/
#   - export/                (the EXPORT-kind vectors + key files)
#   - dump/                  (the DUMP-kind vector directories)
#   - manifest-export.json
#   - manifest-dump.json
```
