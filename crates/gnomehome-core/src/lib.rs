//! Shared building blocks for the GnomeHome Rust services.
//!
//! Each module follows a Python counterpart and the same written contract, so the
//! two languages agree on every row they share through SQLite:
//!
//! | Module | Python | Contract |
//! | --- | --- | --- |
//! | [`identifiers`] | `identifiers.py` | MAC and IP normalization |
//! | [`protected`] | `protected.py` | `testdata/guard_vectors.yaml` |
//! | [`audit`] | `audit.py` | `docs/audit-log.md`, `testdata/audit_vectors.json` |
//! | [`db`] | `db/__init__.py` | connection settings, schema version |
//! | [`time`] | `timeutil.py` | `YYYY-MM-DDTHH:MM:SS.mmmZ` |
//! | [`config`] | `config.py` | the subset of `config/gnomehome.toml` Rust needs |

pub mod audit;
pub mod config;
pub mod db;
pub mod identifiers;
pub mod protected;
pub mod time;

/// Test helpers for this and the other GnomeHome crates (`features = ["testkit"]`).
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;
