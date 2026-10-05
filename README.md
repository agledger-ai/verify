# @agledger/verify

Standalone offline verifier for a **full AGLedger installation dump**: the
per-record `audit_vault` hash chain, the vault checkpoints, the
`org_admin_reads` Merkle log, and the signed key statements that anchor every
vault key, all read from a static NDJSON dump. No engine, no database, no
network. It reads dumps and exports from AGLedger API 2.0.

Built on [`@agledger/verify-core`](https://www.npmjs.com/package/@agledger/verify-core): the per-record (and per-org
schema-event) hash-chain walk is the same body of logic the SDK `/verify`
subpath, the CLI, and the MCP server all run. This package adds the
dump-structural passes the core does not model (checkpoint cross-check, the
org-admin-reads STH + fork detection) and the full-vault loader. The key walk
is verify-core's too.

## Why

The engine signs every state transition (Ed25519 by default, ES256 behind
the server-side opt-in). A customer's auditor
needs an independent verifier that does not trust the engine. If the engine
were compromised, an in-engine "everything is fine" report would be worth
nothing. This package is that escape hatch: it lives outside the engine and
checks a dump the operator produces with the engine's `vault:dump` exporter.

The one thing a dump cannot tell you on its own is which keys to trust: anything
with write access to the database can add a key row and sign entries with it.
So an independent audit pins one vault key it holds or took out of band
(`--trust-anchor`), and the verifier trusts only keys that signed key
statements link to it. Without a pin a clean run still passes, flagged as not
anchored, and never reads as a trusted verdict.

## Install

The package provides the `agledger-verify` binary. An auditor running a one-off
check does not need to install anything:

```bash
npx @agledger/verify <target>
```

For repeated use, or to call it from your own code:

```bash
npm install -g @agledger/verify   # binary on your PATH
npm install @agledger/verify      # library, see "Library" below
```

Node 24 or newer.

## CLI

```bash
agledger-verify <target> [--trust-anchor sha256:<hex>]...
                [--distrusted-key sha256:<hex>[@<instant>]]...
                [--agent-keys <file>]
                [--report-format text|json]
                [--keys <file>] [--require-key-id <id>]
                [--require-supplied-keys]
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
| `0` | Verified. No failures. The verdict says whether the keys were anchored: `trusted` with a `--trust-anchor`, `unanchored` without one. |
| `1` | Verification FAILED. The chain, log, or key statements do not hold up. |
| `2` | Could NOT verify. The input was missing, unreadable, or malformed (a mistyped pin included); no verdict was reached. |

`1` and `2` mean opposite things, so treat only `1` as evidence of tampering.
An audit gate wired to "nonzero means the chain is broken" will otherwise raise
a tamper alarm over a mistyped path. A gate that needs a trusted verdict reads
`verdict` from `--report-format json`, or passes `--trust-anchor`.

### Anchoring keys

A vault key is trusted only when signed **key statements** link it to a key you
pinned. The dump carries them in `vault_key_statements.ndjson`: a genesis for
the install's first key, a succession signed by the old key and the new one at
each rotation, a closure at each retirement. A database writer can add a key
row; it cannot add a statement, because every link is a signature it does not
hold. Pin the SPKI digest of a vault key taken out of band: the installer
prints the first key's, and the Server's `signing-key-digest.js` derives one
from any key you hold.

```bash
agledger-verify ./dump --trust-anchor sha256:15d63684b387235c47fe3a81e3004b928f4ea535236a2c1b47465ce5fdd7ce0e
```

`--trust-anchor` is repeatable. The statements are walked in the dump's write
order (`created_at`, then row id), the rule the engine applies to its own
registry, and each anchored key is held to the window its statements sign
rather than to the registry columns. A row signed by a key the walk does not
reach fails, with the code the engine's own scan reports for it:

| Row | Code |
| --- | --- |
| chain entry | `CHAIN_SIGNING_KEY_UNANCHORED` |
| vault checkpoint | `CHECKPOINT_KEY_UNANCHORED` |
| read-log leaf | `TENANT_READ_KEY_UNANCHORED` |
| read-log tree head | `TENANT_CHECKPOINT_KEY_UNANCHORED` |

Findings about the statements themselves fail the dump too, and are listed
under `key anchoring` in the text report and in `keyTrust.findings` in JSON:
`KEY_STATEMENT_INVALID` (a statement that does not verify or disagrees with
what it is filed under), `KEY_CLOSURE_INVALID` (a retired key with no closure
that counts, or a closure by a key the walk reaches but does not anchor that
retires an anchored key earlier, or with force, than any published closure, as
the engine's scan grades it), and `CHAIN_KEY_WINDOW_DRIFT` (a registry column that differs from
the signed window). A key reached only through a statement this host cannot
compute (Ed25519 history on a FIPS host) is `undecided`, and what it signed is
`CHAIN_UNSUPPORTED_ALGORITHM`, not tamper.

When a key has leaked, pass each entry of the operator's
`VAULT_DISTRUSTED_KEYS` as a `--distrusted-key`: `sha256:<hex>`, optionally
`@<RFC 3339 instant>`, one flag per key. What such a key stored from that
instant on (or, with no instant, from the retirement a trusted key signed for
it) counts for nothing. On an export file, a key statement such a key signed
counts for nothing at any instant, because the write times an export carries
are not signed. A dump's write times are read as the Server reads them, which
holds only for a dump taken from the Server itself. Entry `createdAt` is not
signed either, so the holder of a leaked key can still sign entries dated
before its cutoff, and no offline verifier can tell those from history inside
the key's legitimate window. It needs a `--trust-anchor`.

```bash
# Pinned on the key that succeeded the leaked one.
agledger-verify ./dump --trust-anchor sha256:3f8077ed9d166e62a98b87ac78e44565cdde3c587ccb3d18bc63ddb42fb1f675 \
  --distrusted-key sha256:15d63684b387235c47fe3a81e3004b928f4ea535236a2c1b47465ce5fdd7ce0e@2026-09-30T22:06:09Z
```

A dated entry may sit beside a `--trust-anchor` for the same key, which is
how the Server's key-compromise runbook keeps a leaked key's history: the pin
vouches for what the key stored before the instant, and the entry withdraws
what it stored from then on. An entry with no instant beside a pin for the
same key is refused, as the Server refuses to start with that pair.

```bash
# The leaked key stays pinned for its history before the instant.
agledger-verify ./dump \
  --trust-anchor sha256:15d63684b387235c47fe3a81e3004b928f4ea535236a2c1b47465ce5fdd7ce0e \
  --trust-anchor sha256:3f8077ed9d166e62a98b87ac78e44565cdde3c587ccb3d18bc63ddb42fb1f675 \
  --distrusted-key sha256:15d63684b387235c47fe3a81e3004b928f4ea535236a2c1b47465ce5fdd7ce0e@2026-09-30T22:06:09Z
```

On a dump, what a distrusted key signed outside its trust (from its instant
on, or at any time when no pin reaches it) but stored before a key the walk
trusts retired it is **accounted for**, as the engine's vault scan lists it in
`distrustedEntries`: the distrust entry and that retirement account for it.
It is listed, it is not verified, and it fails nothing, so a dump whose only
such items are accounted for passes with exit `0`. The text report lists the
chain entries under `audit_vault chain` as `accounted for` with the code
`CHAIN_SIGNED_BY_DISTRUSTED_KEY`, and the key statements under `key
anchoring`. In JSON they are `vault.accounted` (capped at 1000, as
`vault.failures` is) with the true total in `vault.accountedCount`, and
`keyTrust.accounted`. Each entry carries `code`, `chain` (`record`, `admin` or
`schema`), `recordId`, `orgId`, `scopeId`, `position`, `keyId` and `detail`.
Accounted entries do not count toward `vault.signedEntries`. Anything the key
signed after that retirement, or under a distrusted key no trusted key has
retired, still fails. An export file has nothing accounted for: such entries
and statements fail there, as they do in the engine's export.

A malformed pin or distrusted key, a key named twice, `--distrusted-key`
without `--trust-anchor`, a pinned key distrusted with no instant, and a
target that does not exist are each refused with exit `2` before anything is
read; the library throws `TypeError` for the same inputs, before it reads the
directory, and for an option `verifyDump` does not read. The Python
`agledger-verify` and `agledger verify` refuse them with the same words and
the same code.

Without a pin nothing is anchored. The chains are still checked against the
dump's own `vault_signing_keys`, so tampering that leaves the keys alone is
still found and a clean dump still passes, but a key written into the database
alone would pass too. The report flags it:

- text: the headline is `[VERIFIED, NOT ANCHORED]`, followed by lines saying
  this is not a trusted verdict and how to get a pin from the operator, and
  `key anchoring` reads `NOT RUN` (a trusted pass is `[PASS]` and a failure
  `[FAIL]`, each with one line saying what it means);
- JSON: `ok` is `true`, `verdict` is `"unanchored"` (`"trusted"` and
  `"failed"` are the others), `keyTrust.status` is `"no_anchor"`, and
  `vault.optionalChecks.key_anchoring` is `"skipped_no_input"`;
- exit code `0`.

An `/audit-export` file reads the same way (`verdict` beside verify-core's
result in JSON). The flags apply to it too, and its statements come from
`exportMetadata.signingKeyStatements` plus any `statements` on keys passed
with `--keys`.

### Vault size

`audit_vault.ndjson` is streamed and verified one chain at a time, so a dump is
bounded by disk rather than by memory. Peak memory is the largest single chain,
not the vault. There is no size ceiling to work around.

Failure lists are capped at `MAX_REPORTED_FAILURES` entries per section, with
the true total in `failureCount` and a `... and N more not shown` line in the
text report. A systemic problem on a large vault produces one failure per
entry, and burying the finding under a million identical lines helps nobody.

### Supplied keys for an export

Without `--keys`, an `/audit-export` file is verified against the signing keys
carried inside that same export. `--keys` supplies them from elsewhere, and
`--require-supplied-keys` refuses the export's own:

```bash
# The raw response envelope is accepted as-is; .data is unwrapped, and the
# key statements it carries are walked with the export's.
curl -s https://ledger.example.com/v1/verification-keys > keys.json

agledger-verify export.json --keys keys.json --require-supplied-keys \
  --trust-anchor sha256:15d63684b387235c47fe3a81e3004b928f4ea535236a2c1b47465ce5fdd7ce0e
```

Where a key came from is not whether it is trusted: keys fetched from the
Server come from the same database an attacker would write to. The report's
`key provenance: supplied=N embedded=M` line says where each key came from, and
only the `--trust-anchor` walk says a key is trusted.

`--keys` accepts a `{keyId: SPKI-DER-base64}` map, a
`[{keyId, publicKey, ...}]` list, or the raw `GET /v1/verification-keys`
response envelope. `--require-key-id <id>` additionally rejects an
otherwise-valid export signed by a retired or unexpected key. The key-policy
flags apply to `/audit-export` files only; a dump directory carries its own
signed key history (`vault_signing_keys.ndjson` and
`vault_key_statements.ndjson`) and rejects them.

### Agent signatures

An agent that authenticates with an ephemeral cert can sign each request body
it sends. The Server checks that signature, then seals it into the chain entry
as `predicate.on_behalf_of.agent_signature`, beside the RFC 7638 thumbprint of
the cert's public key. The envelope signature proves the Server wrote that. To
prove the agent itself signed, without taking the Server's word for it, the
signature is re-verified offline under the cert's public key.

Where that key comes from depends on what you are verifying:

- **A dump not scoped to one org** carries it. The Server records every cert
  it issues as an `EPHEMERAL_CERT_ISSUED` entry on the platform-ops chain, and
  from API 1.8.0 that entry signs the cert's `publicKeyJwk` beside its
  `publicKeyThumbprint`. The verifier takes each such key once the
  platform-ops chain has verified clean (hash chain, vault signatures and
  checkpoints) and only from an entry whose vault signature checked, so it
  uses no key the vault key did not sign. No flag is needed.
- **An org-scoped dump** (`--org <id>` on the dump tool) leaves the
  platform-ops chain out, and **a per-record `/audit-export`** does not
  include it either. Neither carries cert keys.
- **A cert issued by a Server older than 1.8.0** has only its thumbprint on
  the chain.

For the last two cases, pass the keys:

```bash
agledger-verify ./dump --agent-keys agent-keys.json
agledger-verify export.json --agent-keys agent-keys.json
```

They come from the agent: the `publicKeyJwk` it sent to
`POST /v1/auth/oidc/cert`, which is also the `cnf.jwk` claim inside the
`certJws` it got back. On a dump they are used beside the keys the dump
signs. The file holds one Ed25519 JWK, a list of them, or a
`{"keys": [...]}` JWK Set, and any entry may wrap its key as
`{"publicKeyJwk": {...}}`:

```json
[{ "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": "BKOgK3KibE8BZH8SXTX9dmAXcwgocTMHIv-R_eRB2lo" } }]
```

A key is matched to an entry only through the thumbprint that entry signed, so
a key for some other cert matches nothing, and where the file came from needs
no trust. The report gives `present` (entries carrying an agent signature) and
`verified` (those re-checked and found good), and says whether the check ran at
all: in the text report on the `agent sigs` / `agent signatures` line, in JSON
as `optionalChecks.agent_signature` and `agentSignatures` (under `vault` for a
dump, beside `certKeysFromChain`, the number of cert keys the dump signed).
`present > verified` on a passing report means some signatures name a cert
whose key was not at hand, never that they failed. One that does not verify
fails `CHAIN_AGENT_SIGNATURE_INVALID`. With no key for any of them the check
is reported as not run and no verdict changes. The text line reads `all
re-verified` only when every agent signature on the chain was; otherwise it
says how many were NOT verified and why, including when none of the supplied
keys matches a sealed cert thumbprint. A file that holds no keys, or
anything that is not an Ed25519 JWK, is exit `2`.

## Library

```ts
import { verifyDumpStreaming } from '@agledger/verify';

const report = verifyDumpStreaming('/path/to/dump', undefined, {
  trustAnchors: ['sha256:15d63684b387235c47fe3a81e3004b928f4ea535236a2c1b47465ce5fdd7ce0e'],
});
console.log(report.verdict); // 'trusted' | 'unanchored' | 'failed'
if (report.verdict !== 'trusted') {
  console.error(JSON.stringify(report, null, 2));
  process.exit(1);
}
```

`ok` is false only for `failed`. Without `trustAnchors` a clean dump is
`unanchored`, with `keyTrust.status` `no_anchor`: a pass, not a trusted one. `distrustedKeys` takes
the `VAULT_DISTRUSTED_KEYS` entries, as strings or parsed. A malformed anchor
or distrusted key throws `TypeError`, as do `distrustedKeys` without
`trustAnchors` and a pinned key distrusted with no instant, each before the
directory is read. A dump's accounted entries are in `report.vault.accounted`
(`AccountedEntry`, with `ACCOUNTED_ENTRY_CODE` as their code) and
`report.vault.accountedCount`.

To supply cert keys the dump does not sign itself, add them to the options:

```ts
import { verifyDumpStreaming } from '@agledger/verify';

const agentKey = { kty: 'OKP', crv: 'Ed25519', x: 'BKOgK3KibE8BZH8SXTX9dmAXcwgocTMHIv-R_eRB2lo' } as const;
const report = verifyDumpStreaming('/path/to/dump', undefined, { agentKeys: [agentKey] });

console.log(report.vault.optionalChecks.agent_signature); // 'applied' once a key matched
console.log(report.vault.agentSignatures); // e.g. { present: 12, verified: 6 }
```

`verifyDumpStreaming` is the one to reach for: it streams `audit_vault.ndjson`
instead of materializing it. `loadDump` + `verifyDump` still exist and produce
the same report, but they hold every row, so keep them for dumps small enough
to fit in heap.

`walkDumpKeys` runs the key walk on its own, and `verifyVaultChains` /
`verifyOrgAdminReadsChains` take its result. The shared core's per-record
export path and the low-level primitives (`verifyAuditExport`, `verifyChain`,
`computeKeyTrust`, `orgReadLeafHash`, `orgReadMerkleRoot`,
`verifyOrgReadInclusion`, `verifyCoseSign1`, and others) are re-exported so a
caller need not add a second dependency.

## What is verified

- **`audit_vault` per-record chain** (via `verify-core`): chain_position
  monotonicity, payload_hash = sha256(cose_sign1), previous_hash linkage, the
  signed COSE protected-header chain-claim cross-check, the envelope
  signature (Ed25519 or ES256, dispatched from the trusted key material),
  plus the input-gated checks: binding-integrity
  (`CHAIN_PAYLOAD_BINDING_MISMATCH`, which also holds a row copy of
  `on_behalf_of` or `traceparent` to the value the entry signed), OIDC-actor
  cross-check (`CHAIN_OIDC_ACTOR_MISMATCH`), actor attribution
  (`CHAIN_ACTOR_ATTRIBUTION_MISMATCH`: the `actor_key_id`, `actor_role` and
  `actor_owner_id` a report displays against the actor claim the entry signed),
  temporal key-validity (`CHAIN_KEY_EXPIRED`, against the signed window once
  anchored), key anchoring (`CHAIN_SIGNING_KEY_UNANCHORED`), and the agent signatures
  (`CHAIN_AGENT_SIGNATURE_INVALID`) under the cert keys the dump signs or
  `--agent-keys` supplies.
- **Key statements**: walked from the `--trust-anchor` pins in write order;
  see "Anchoring keys".
- **Vault checkpoints**: the anchor row matches the live entry at its position
  and its signature verifies under an anchored key. A checkpoint without a
  matching `audit_vault` row is evidence of out-of-band TRUNCATE/DELETE
  (`CHECKPOINT_ROW_MISSING`). The claim signed inside the envelope must say
  what the row says (position, tip hash, record subject, key id), or it is
  `CHECKPOINT_CLAIM_MISMATCH`: the hash cross-check reads the columns, so a
  rewritten column pair beside an intact envelope would otherwise pass.
- **`org_admin_reads` chain**: leaf_hash is the RFC 9162 leaf hash of the
  envelope, sha256(0x00 || cose_sign1); leaf_index is gap-free per org; each
  leaf's signed claim gives its position, the previous leaf's hash and the
  record read, as its row does (`TENANT_READ_CLAIM_MISMATCH`); and each leaf's
  signature verifies under the anchored key its envelope names
  (`TENANT_READ_SIGNATURE_INVALID`).
- **STH (signed tree head) checkpoints**: the RFC 9162 root over the first
  `tree_size` leaves matches the `root_hash` column, the signed claim gives the
  same size, root and key id (`TENANT_CHECKPOINT_CLAIM_MISMATCH`), and the
  signature verifies. An
  inclusion proof from `GET /v1/audit/org-reads/checkpoints/{id}/proof` checks
  with the re-exported `verifyOrgReadInclusion`.
- **Unsigned rows**, graded as the engine grades them. The install began
  signing at the earliest `activated_at` in `vault_signing_keys`, retired keys
  included. From then on every writer holds a registered key, so an unsigned
  row written at or after that instant is a break: `CHAIN_ENTRY_UNSIGNED` for a
  chain entry, `CHECKPOINT_UNSIGNED` for a vault checkpoint,
  `TENANT_READ_LEAF_UNSIGNED` for a read-log leaf (its envelope kid is the
  unsigned sentinel `0000000000000000`) and `TENANT_CHECKPOINT_UNSIGNED` for a
  tree head. An unsigned entry or leaf after a signed one in the same chain or
  org log is a break whatever its time. Unsigned rows from before the first key
  activation stay reduced coverage, so an install that never registered a key
  still verifies.
- **Engine-fork detection**: two checkpoints at the same `tree_size` carrying
  different `root_hash` is `TENANT_CHECKPOINT_FORK`.

## Fail-closed posture

- An **empty or truncated vault** (zero entries) does NOT verify clean. It
  reports `CHAIN_EMPTY`.
- A vault row with no `cose_sign1` carries no signed envelope (every row in
  export format 2.0 has one, so it was written by an engine that predates the
  envelope or had the column removed). It fails `UNSUPPORTED_FORMAT` rather than
  being parsed best-effort.

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
| `vault_key_statements.ndjson` | Signed key statements (genesis, succession, closure) with their write time. |
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
