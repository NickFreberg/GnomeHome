# Audit log specification (v1)

GnomeHome records every login and action in an append-only, hash-chained audit log (NFR-06). This
document is the contract that every writer follows. Python follows it today in `python/gnomehome/audit.py`,
and Rust will follow it once the playbook engine and API become writers. Both must reproduce every hash in
[`testdata/audit_vectors.json`](../testdata/audit_vectors.json).

## Table

`audit_log` in the shared SQLite database (migration `0001_core_schema.sql`):

| Column | Meaning |
| --- | --- |
| `seq` | 1, 2, 3, … with no gaps |
| `ts` | UTC timestamp, `YYYY-MM-DDTHH:MM:SS.mmmZ` |
| `actor` | Who acted, such as `system:scan` or `user:<name>` |
| `action` | What was attempted, such as `scan.start` or `guard.refused` |
| `target` | What it was aimed at, or NULL. Protected assets appear only as `protected:<label>`, never by MAC or IP |
| `result` | `success`, `failure`, or `refused` |
| `details` | Compact JSON text or NULL. The hash covers this text exactly as stored |
| `prev_hash` | The previous row's `hash`. Row 1 uses 64 zeros |
| `hash` | Lowercase hex SHA-256 of the canonical encoding below |

## Canonical encoding

The hash input is the bytes:

```
gnomehome-audit-v1\n
<field>\n   for each of: seq, ts, actor, action, target, result, details, prev_hash
```

Each field is encoded as:

- NULL: the single byte `-` (so NULL and the empty string differ: `-` vs `0:`)
- anything else: `<length in bytes of its UTF-8 form, in decimal>:<the UTF-8 bytes>`
- `seq` is encoded as its decimal string, such as `1:7` for seq 7

Example (row 1 of the vectors):

```
gnomehome-audit-v1
1:1
24:2026-10-11T14:00:00.000Z
11:system:scan
10:scan.start
-
7:success
30:{"kind":"service","targets":1}
64:0000000000000000000000000000000000000000000000000000000000000000
```

`hash = sha256(those bytes)` as lowercase hex, which is
`483f95558c303cb7a4d1bbc936576ff90bc70740c562a372ff3a269cd823c055`.

Length prefixes make the encoding unambiguous without escaping rules, so the two languages can't
disagree about quoting or Unicode. You can check row 1 by hand:

```
printf 'gnomehome-audit-v1\n1:1\n24:2026-10-11T14:00:00.000Z\n11:system:scan\n10:scan.start\n-\n7:success\n30:{"kind":"service","targets":1}\n64:0000000000000000000000000000000000000000000000000000000000000000\n' | sha256sum
```

## Writing

1. Start a write transaction **before** reading the last row (`BEGIN IMMEDIATE` in SQLite), so two writers
   can't both chain onto the same row.
2. Read the last row's `seq` and `hash` (or use seq 0 and the genesis hash).
3. Insert the new row with `seq + 1`, `prev_hash = last hash`, and the computed `hash`.
4. Commit.

The schema enforces append-only (UPDATE and DELETE are refused), contiguous `seq`, and correct `prev_hash`
linking. SQLite can't compute SHA-256, so the hash itself is checked by `just audit-verify`.

Don't append inside a long-running write transaction: if that transaction rolls back, the audit entry goes with it.

## Verifying

`just audit-verify` walks the chain from row 1 and reports any gap in `seq`, any broken `prev_hash`
link, and any row whose recomputed hash differs from the stored one.

## Known limits

- Someone who can rewrite the whole database file can build a new, internally consistent chain, and
  truncating the newest rows can't be detected from the database alone. The fix is to anchor the latest
  hash outside the Pi, which comes in a later phase (the nightly upload to Azure, or a signed checkpoint).
- The triggers stop accidents and casual edits. They don't stop anyone who can run `DROP TRIGGER`. That's what the hash chain is for.
