//! The append-only, hash-chained audit log (NFR-06), following `docs/audit-log.md`.
//!
//! Rust and Python write to the same `audit_log` table and must produce identical
//! hashes for `testdata/audit_vectors.json`. A protected device appears in `target`
//! only as `protected:<label>`, never by MAC or IP.

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::db::immediate;
use crate::time::utc_now;

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const ENCODING_TAG: &[u8] = b"gnomehome-audit-v1\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Failure,
    Refused,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Failure => "failure",
            Outcome::Refused => "refused",
        }
    }
}

/// One stored row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub seq: i64,
    pub ts: String,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub result: String,
    pub details: Option<String>,
    pub prev_hash: String,
    pub hash: String,
}

/// Length-prefixed encoding of every field: `<byte length>:<UTF-8 bytes>\n`, or `-\n` for NULL.
#[allow(clippy::too_many_arguments)]
pub fn canonical_bytes(
    seq: i64,
    ts: &str,
    actor: &str,
    action: &str,
    target: Option<&str>,
    result: &str,
    details: Option<&str>,
    prev_hash: &str,
) -> Vec<u8> {
    let seq_text = seq.to_string();
    let fields = [
        Some(seq_text.as_str()),
        Some(ts),
        Some(actor),
        Some(action),
        target,
        Some(result),
        details,
        Some(prev_hash),
    ];
    let mut out = ENCODING_TAG.to_vec();
    for field in fields {
        match field {
            None => out.extend_from_slice(b"-\n"),
            Some(value) => {
                out.extend_from_slice(value.len().to_string().as_bytes());
                out.push(b':');
                out.extend_from_slice(value.as_bytes());
                out.push(b'\n');
            }
        }
    }
    out
}

impl Entry {
    pub fn compute_hash(&self) -> String {
        let bytes = canonical_bytes(
            self.seq,
            &self.ts,
            &self.actor,
            &self.action,
            self.target.as_deref(),
            &self.result,
            self.details.as_deref(),
            &self.prev_hash,
        );
        hex(&Sha256::digest(bytes))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Compact, key-sorted JSON, the same text Python's `encode_details` produces for
/// strings, integers, booleans, and nested objects. Avoid floats in audit details:
/// the two languages print some of them differently.
pub fn encode_details(details: &Value) -> String {
    // serde_json's default map is a BTreeMap, so keys come out sorted by code point.
    serde_json::to_string(details).expect("JSON values always serialize")
}

/// Appends one entry. Call it outside any other write transaction, so a rollback
/// elsewhere can't take the audit entry with it.
pub fn append(
    conn: &mut Connection,
    actor: &str,
    action: &str,
    target: Option<&str>,
    outcome: Outcome,
    details: Option<&Value>,
) -> rusqlite::Result<Entry> {
    assert!(
        !actor.is_empty() && !action.is_empty(),
        "audit entries need an actor and an action"
    );
    let details = details.map(encode_details);
    // BEGIN IMMEDIATE takes the write lock before reading the last hash, so two
    // writers (in any process or language) can't fork the chain.
    immediate(conn, |tx| {
        let last: Option<(i64, String)> = tx
            .query_row(
                "SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (seq, prev_hash) = match last {
            Some((seq, hash)) => (seq + 1, hash),
            None => (1, GENESIS_HASH.to_owned()),
        };
        let mut entry = Entry {
            seq,
            ts: utc_now(),
            actor: actor.to_owned(),
            action: action.to_owned(),
            target: target.map(str::to_owned),
            result: outcome.as_str().to_owned(),
            details,
            prev_hash,
            hash: String::new(),
        };
        entry.hash = entry.compute_hash();
        tx.execute(
            "INSERT INTO audit_log (seq, ts, actor, action, target, result, details, prev_hash, hash) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                entry.seq,
                entry.ts,
                entry.actor,
                entry.action,
                entry.target,
                entry.result,
                entry.details,
                entry.prev_hash,
                entry.hash
            ],
        )?;
        Ok(entry)
    })
}

/// The target string for a protected device: its label, never an identifier.
pub fn protected_target(label: &str) -> String {
    format!("protected:{label}")
}

#[derive(Debug, Default)]
pub struct Verification {
    pub rows: i64,
    pub problems: Vec<String>,
}

impl Verification {
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Recomputes the whole chain and reports any gap, broken link, or modified row.
pub fn verify(conn: &Connection) -> rusqlite::Result<Verification> {
    let mut result = Verification::default();
    let mut expected_seq = 1;
    let mut prev_hash = GENESIS_HASH.to_owned();
    let mut stmt = conn.prepare(
        "SELECT seq, ts, actor, action, target, result, details, prev_hash, hash FROM audit_log ORDER BY seq",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(Entry {
            seq: r.get(0)?,
            ts: r.get(1)?,
            actor: r.get(2)?,
            action: r.get(3)?,
            target: r.get(4)?,
            result: r.get(5)?,
            details: r.get(6)?,
            prev_hash: r.get(7)?,
            hash: r.get(8)?,
        })
    })?;
    for row in rows {
        let entry = row?;
        result.rows += 1;
        if entry.seq != expected_seq {
            result.problems.push(format!(
                "seq {}: expected {expected_seq} (rows missing?)",
                entry.seq
            ));
        }
        if entry.prev_hash != prev_hash {
            result.problems.push(format!(
                "seq {}: prev_hash does not match the previous row's hash",
                entry.seq
            ));
        }
        if entry.compute_hash() != entry.hash {
            result.problems.push(format!(
                "seq {}: hash mismatch (row was modified)",
                entry.seq
            ));
        }
        if result.problems.len() >= 20 {
            result
                .problems
                .push("... stopping after too many problems".to_owned());
            break;
        }
        expected_seq = entry.seq + 1;
        prev_hash = entry.hash;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{migrated_db, repo_root};
    use serde_json::json;

    fn vectors() -> Value {
        let text =
            std::fs::read_to_string(repo_root().join("testdata/audit_vectors.json")).unwrap();
        serde_json::from_str(&text).unwrap()
    }

    fn entry(v: &Value) -> Entry {
        Entry {
            seq: v["seq"].as_i64().unwrap(),
            ts: v["ts"].as_str().unwrap().to_owned(),
            actor: v["actor"].as_str().unwrap().to_owned(),
            action: v["action"].as_str().unwrap().to_owned(),
            target: v["target"].as_str().map(str::to_owned),
            result: v["result"].as_str().unwrap().to_owned(),
            details: v["details"].as_str().map(str::to_owned),
            prev_hash: v["prev_hash"].as_str().unwrap().to_owned(),
            hash: v["hash"].as_str().unwrap().to_owned(),
        }
    }

    #[test]
    fn shared_vectors_hash_identically() {
        for v in vectors()["entries"].as_array().unwrap() {
            let e = entry(v);
            assert_eq!(e.compute_hash(), e.hash, "seq {}", e.seq);
            if let Some(canonical) = v["canonical_utf8"].as_str() {
                let bytes = canonical_bytes(
                    e.seq,
                    &e.ts,
                    &e.actor,
                    &e.action,
                    e.target.as_deref(),
                    &e.result,
                    e.details.as_deref(),
                    &e.prev_hash,
                );
                assert_eq!(bytes, canonical.as_bytes());
            }
        }
    }

    #[test]
    fn details_encoding_matches_python() {
        let details = json!({"z": 1, "a": "café", "m": {"y": true, "b": null}});
        assert_eq!(
            encode_details(&details),
            r#"{"a":"café","m":{"b":null,"y":true},"z":1}"#
        );
    }

    #[test]
    fn append_chains_and_verify_detects_tampering() {
        let (_dir, path) = migrated_db();
        let mut conn = crate::db::open(&path).unwrap();
        let first = append(
            &mut conn,
            "system:test",
            "test.one",
            None,
            Outcome::Success,
            None,
        )
        .unwrap();
        let details = json!({"attempted_action": "quarantine", "matched_on": "mac"});
        let second = append(
            &mut conn,
            "system:test",
            "guard.refused",
            Some(&protected_target("Work laptop")),
            Outcome::Refused,
            Some(&details),
        )
        .unwrap();
        assert_eq!(first.prev_hash, GENESIS_HASH);
        assert_eq!(second.prev_hash, first.hash);
        assert!(verify(&conn).unwrap().ok());

        // The schema refuses edits, so tamper the way an attacker would: drop the trigger.
        conn.execute_batch("DROP TRIGGER audit_log_no_update")
            .unwrap();
        conn.execute(
            "UPDATE audit_log SET actor = 'user:someone' WHERE seq = 1",
            [],
        )
        .unwrap();
        let report = verify(&conn).unwrap();
        assert!(!report.ok());
        assert!(report.problems[0].contains("hash mismatch"));
    }

    #[test]
    fn schema_blocks_updates_and_deletes() {
        let (_dir, path) = migrated_db();
        let mut conn = crate::db::open(&path).unwrap();
        append(
            &mut conn,
            "system:test",
            "test.one",
            None,
            Outcome::Success,
            None,
        )
        .unwrap();
        assert!(
            conn.execute("UPDATE audit_log SET actor = 'x'", [])
                .is_err()
        );
        assert!(conn.execute("DELETE FROM audit_log", []).is_err());
    }
}
