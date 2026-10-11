//! Authentication and sessions (NFR-01, NFR-06).
//!
//! - **Passwords**: Argon2id with OWASP's minimum parameters for a small machine
//!   (19 MiB, 2 passes, 1 lane), stored in PHC format.
//! - **MFA**: every login needs a TOTP code (RFC 6238: SHA-1, 6 digits, 30 seconds),
//!   accepted one step either side for clock drift, and never twice.
//! - **Sessions**: a random 256-bit token in a cookie; only its SHA-256 is stored.
//!   30 minutes idle, 12 hours at most. Each session has its own CSRF token.
//! - **Lockout**: 5 failed logins lock the account for 15 minutes.
//!
//! Secrets are compared in constant time, and an unknown username costs the same
//! Argon2 work as a known one, so timing doesn't reveal which accounts exist.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use chrono::{DateTime, Duration, Utc};
use gnomehome_core::time::{format_ts, parse_ts};
use hmac::{Hmac, Mac};
use rusqlite::{Connection, OptionalExtension, params};
use sha1::Sha1;
use sha2::{Digest, Sha256};

pub const SESSION_IDLE: Duration = Duration::minutes(30);
pub const SESSION_MAX: Duration = Duration::hours(12);
/// Approving a disruptive action needs a TOTP check this recent.
pub const FRESH_MFA: Duration = Duration::minutes(5);
pub const MAX_FAILURES: i64 = 5;
pub const LOCKOUT: Duration = Duration::minutes(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Viewer,
    Analyst,
    Admin,
}

impl Role {
    pub fn parse(text: &str) -> Option<Role> {
        match text {
            "viewer" => Some(Role::Viewer),
            "analyst" => Some(Role::Analyst),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Analyst => "analyst",
            Role::Admin => "admin",
        }
    }
}

fn argon2() -> Argon2<'static> {
    let params = Params::new(19 * 1024, 2, 1, None).expect("valid Argon2 parameters");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("the OS random number generator is available");
    buf
}

pub fn hash_password(password: &str) -> String {
    let salt = SaltString::encode_b64(&random_bytes::<16>()).expect("16 bytes is a valid salt");
    argon2()
        .hash_password(password.as_bytes(), &salt)
        .expect("hashing a password with valid parameters")
        .to_string()
}

pub fn verify_password(password: &str, phc: &str) -> bool {
    PasswordHash::new(phc)
        .map(|hash| argon2().verify_password(password.as_bytes(), &hash).is_ok())
        .unwrap_or(false)
}

/// Spends the same Argon2 work as a real check, for unknown usernames.
pub fn burn_password_check(password: &str) {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let hash = DUMMY.get_or_init(|| hash_password("a password nobody has"));
    let _ = verify_password(password, hash);
}

pub fn password_ok(password: &str) -> Result<(), &'static str> {
    if password.chars().count() < 12 {
        return Err("use at least 12 characters");
    }
    if password.chars().count() > 256 {
        return Err("use at most 256 characters");
    }
    Ok(())
}

// ------------------------------------------------------------------ TOTP

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            out.push(BASE32[((buffer >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(BASE32[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in text.trim_end_matches('=').bytes() {
        let value = BASE32.iter().position(|&b| b == c.to_ascii_uppercase())? as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            out.push((buffer >> (bits - 8)) as u8);
            bits -= 8;
        }
    }
    Some(out)
}

pub fn new_totp_secret() -> String {
    base32_encode(&random_bytes::<20>())
}

/// The 6-digit code for one 30-second step.
pub fn totp_code(secret: &[u8], step: i64) -> u32 {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let value = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    value % 1_000_000
}

/// Checks a code against the current step and one step either side. Returns the
/// matching step, which must be newer than the last one used (no replays).
pub fn verify_totp(
    secret_b32: &str,
    code: &str,
    now: DateTime<Utc>,
    last_step: i64,
) -> Option<i64> {
    let code = code.trim();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let wanted: u32 = code.parse().ok()?;
    let secret = base32_decode(secret_b32)?;
    let step = now.timestamp().div_euclid(30);
    (step - 1..=step + 1)
        .filter(|s| *s > last_step)
        .find(|s| constant_time_eq(&totp_code(&secret, *s).to_be_bytes(), &wanted.to_be_bytes()))
}

pub fn otpauth_uri(username: &str, secret: &str) -> String {
    format!(
        "otpauth://totp/GnomeHome:{username}?secret={secret}&issuer=GnomeHome&algorithm=SHA1&digits=6&period=30"
    )
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn token_hash(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

// ------------------------------------------------------------------ users and sessions

#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub role: Role,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub user: User,
    pub csrf: String,
    pub expires_at: DateTime<Utc>,
    pub mfa_at: DateTime<Utc>,
}

impl Session {
    pub fn mfa_fresh(&self, now: DateTime<Utc>) -> bool {
        now - self.mfa_at <= FRESH_MFA
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum LoginError {
    /// Wrong username, password, or code. Deliberately not more specific.
    Invalid,
    Locked(String),
}

pub fn valid_username(name: &str) -> bool {
    (2..=32).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

pub fn add_user(
    conn: &Connection,
    username: &str,
    password: &str,
    role: Role,
    now: DateTime<Utc>,
) -> Result<String, String> {
    if !valid_username(username) {
        return Err("usernames are 2-32 lowercase letters, digits, dashes, or underscores".into());
    }
    password_ok(password).map_err(str::to_owned)?;
    let secret = new_totp_secret();
    conn.execute(
        "INSERT INTO app_user (username, password_hash, role, totp_secret, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![username, hash_password(password), role.as_str(), secret, format_ts(now)],
    )
    .map_err(|e| match e {
        rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation => {
            format!("a user named {username:?} already exists")
        }
        other => other.to_string(),
    })?;
    Ok(secret)
}

/// One `app_user` row, as the login check needs it.
struct Account {
    id: i64,
    hash: String,
    role: String,
    secret: String,
    disabled: i64,
    failures: i64,
    locked_until: Option<String>,
    last_step: i64,
}

/// Checks a password and code. On success, creates a session and returns its cookie token.
pub fn login(
    conn: &Connection,
    username: &str,
    password: &str,
    code: &str,
    now: DateTime<Utc>,
) -> Result<(String, Session), LoginError> {
    let row = conn
        .query_row(
            "SELECT id, password_hash, role, totp_secret, disabled, failed_logins, locked_until, last_totp_step \
             FROM app_user WHERE username = ?1",
            [username],
            |r| {
                Ok(Account {
                    id: r.get(0)?,
                    hash: r.get(1)?,
                    role: r.get(2)?,
                    secret: r.get(3)?,
                    disabled: r.get(4)?,
                    failures: r.get(5)?,
                    locked_until: r.get(6)?,
                    last_step: r.get(7)?,
                })
            },
        )
        .optional()
        .map_err(|_| LoginError::Invalid)?;
    let Some(Account {
        id,
        hash,
        role,
        secret,
        disabled,
        failures,
        locked_until,
        last_step,
    }) = row
    else {
        burn_password_check(password);
        return Err(LoginError::Invalid);
    };
    if let Some(until) = locked_until.as_deref().and_then(parse_ts)
        && until > now
    {
        return Err(LoginError::Locked(format_ts(until)));
    }
    let password_good = verify_password(password, &hash);
    let step = if password_good {
        verify_totp(&secret, code, now, last_step)
    } else {
        None
    };
    let Some(step) = step.filter(|_| disabled == 0) else {
        let failures = failures + 1;
        let lock = (failures >= MAX_FAILURES).then(|| format_ts(now + LOCKOUT));
        let _ = conn.execute(
            "UPDATE app_user SET failed_logins = ?1, locked_until = ?2 WHERE id = ?3",
            params![if lock.is_some() { 0 } else { failures }, lock, id],
        );
        return Err(LoginError::Invalid);
    };
    conn.execute(
        "UPDATE app_user SET failed_logins = 0, locked_until = NULL, last_totp_step = ?1 WHERE id = ?2",
        params![step, id],
    )
    .map_err(|_| LoginError::Invalid)?;
    let token = hex(&random_bytes::<32>());
    let csrf = hex(&random_bytes::<16>());
    let expires = now + SESSION_IDLE;
    conn.execute(
        "INSERT INTO app_session (token_hash, user_id, csrf_token, created_at, last_seen, expires_at, mfa_at) \
         VALUES (?1, ?2, ?3, ?4, ?4, ?5, ?4)",
        params![token_hash(&token), id, csrf, format_ts(now), format_ts(expires)],
    )
    .map_err(|_| LoginError::Invalid)?;
    let user = User {
        id,
        username: username.to_owned(),
        role: Role::parse(&role).unwrap_or(Role::Viewer),
    };
    Ok((
        token,
        Session {
            user,
            csrf,
            expires_at: expires,
            mfa_at: now,
        },
    ))
}

/// The session for a cookie token, sliding its idle expiry forward. Expired sessions
/// are deleted.
pub fn session(conn: &Connection, token: &str, now: DateTime<Utc>) -> Option<Session> {
    let hash = token_hash(token);
    let row: (i64, String, String, String, String, String, i64) = conn
        .query_row(
            "SELECT u.id, u.username, u.role, s.csrf_token, s.created_at, s.mfa_at, u.disabled \
             FROM app_session s JOIN app_user u ON u.id = s.user_id \
             WHERE s.token_hash = ?1 AND s.expires_at > ?2",
            params![hash, format_ts(now)],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            },
        )
        .optional()
        .ok()
        .flatten()?;
    let (id, username, role, csrf, created, mfa_at, disabled) = row;
    let created = parse_ts(&created)?;
    if disabled != 0 || now - created > SESSION_MAX {
        let _ = conn.execute("DELETE FROM app_session WHERE token_hash = ?1", [&hash]);
        return None;
    }
    let expires = (now + SESSION_IDLE).min(created + SESSION_MAX);
    let _ = conn.execute(
        "UPDATE app_session SET last_seen = ?1, expires_at = ?2 WHERE token_hash = ?3",
        params![format_ts(now), format_ts(expires), hash],
    );
    let _ = conn.execute(
        "DELETE FROM app_session WHERE expires_at <= ?1",
        [format_ts(now)],
    );
    Some(Session {
        user: User {
            id,
            username,
            role: Role::parse(&role)?,
        },
        csrf,
        expires_at: expires,
        mfa_at: parse_ts(&mfa_at)?,
    })
}

/// A fresh TOTP check inside a session, needed before approving disruptive actions.
pub fn reverify(
    conn: &Connection,
    token: &str,
    user_id: i64,
    code: &str,
    now: DateTime<Utc>,
) -> bool {
    let row: Option<(String, i64)> = conn
        .query_row(
            "SELECT totp_secret, last_totp_step FROM app_user WHERE id = ?1",
            [user_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .ok()
        .flatten();
    let Some((secret, last)) = row else {
        return false;
    };
    let Some(step) = verify_totp(&secret, code, now, last) else {
        return false;
    };
    let _ = conn.execute(
        "UPDATE app_user SET last_totp_step = ?1 WHERE id = ?2",
        params![step, user_id],
    );
    let _ = conn.execute(
        "UPDATE app_session SET mfa_at = ?1 WHERE token_hash = ?2",
        params![format_ts(now), token_hash(token)],
    );
    true
}

pub fn logout(conn: &Connection, token: &str) {
    let _ = conn.execute(
        "DELETE FROM app_session WHERE token_hash = ?1",
        [token_hash(token)],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnomehome_core::testkit::migrated_db;

    #[test]
    fn rfc6238_test_vector() {
        // RFC 6238 appendix B, SHA-1, T = 59 s: 94287082, whose last six digits are 287082.
        assert_eq!(totp_code(b"12345678901234567890", 1), 287_082);
        assert_eq!(
            base32_encode(b"12345678901234567890"),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
        assert_eq!(
            base32_decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(),
            b"12345678901234567890"
        );
    }

    #[test]
    fn passwords_hash_and_verify() {
        let hash = hash_password("correct horse battery");
        assert!(hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(verify_password("correct horse battery", &hash));
        assert!(!verify_password("wrong", &hash));
        assert!(password_ok("short").is_err());
    }

    fn code_at(secret: &str, now: DateTime<Utc>) -> String {
        format!(
            "{:06}",
            totp_code(&base32_decode(secret).unwrap(), now.timestamp() / 30)
        )
    }

    #[test]
    fn login_needs_password_and_code_and_locks_out() {
        let (_dir, path) = migrated_db();
        let conn = gnomehome_core::db::open(&path).unwrap();
        let t0 = parse_ts("2026-10-11T12:00:00.000Z").unwrap();
        let secret = add_user(&conn, "owner", "correct horse battery", Role::Admin, t0).unwrap();
        assert!(add_user(&conn, "owner", "correct horse battery", Role::Admin, t0).is_err());

        let code = code_at(&secret, t0);
        assert_eq!(
            login(&conn, "owner", "nope", &code, t0).unwrap_err(),
            LoginError::Invalid
        );
        assert_eq!(
            login(&conn, "ghost", "x", &code, t0).unwrap_err(),
            LoginError::Invalid
        );
        let (token, s) = login(&conn, "owner", "correct horse battery", &code, t0).unwrap();
        assert_eq!(s.user.role, Role::Admin);
        // The same code can't be used again.
        assert!(login(&conn, "owner", "correct horse battery", &code, t0).is_err());

        let later = t0 + Duration::minutes(10);
        let found = session(&conn, &token, later).unwrap();
        assert_eq!(found.csrf, s.csrf);
        assert!(!found.mfa_fresh(later));
        assert!(session(&conn, &token, later + Duration::minutes(31)).is_none()); // idle timeout
        assert!(session(&conn, "not-a-token", later).is_none());

        let t1 = t0 + Duration::hours(1);
        for _ in 0..MAX_FAILURES {
            let _ = login(&conn, "owner", "wrong password!!", "000000", t1);
        }
        let good = code_at(&secret, t1);
        assert!(matches!(
            login(&conn, "owner", "correct horse battery", &good, t1),
            Err(LoginError::Locked(_))
        ));
        let t2 = t1 + LOCKOUT + Duration::minutes(1);
        assert!(
            login(
                &conn,
                "owner",
                "correct horse battery",
                &code_at(&secret, t2),
                t2
            )
            .is_ok()
        );
    }

    #[test]
    fn sessions_end_after_twelve_hours_however_active() {
        let (_dir, path) = migrated_db();
        let conn = gnomehome_core::db::open(&path).unwrap();
        let t0 = parse_ts("2026-10-11T08:00:00.000Z").unwrap();
        let secret = add_user(&conn, "owner", "correct horse battery", Role::Viewer, t0).unwrap();
        let (token, _) = login(
            &conn,
            "owner",
            "correct horse battery",
            &code_at(&secret, t0),
            t0,
        )
        .unwrap();
        let mut now = t0;
        while now + Duration::minutes(20) < t0 + Duration::hours(12) {
            now += Duration::minutes(20);
            assert!(session(&conn, &token, now).is_some(), "{now}");
        }
        assert!(
            session(
                &conn,
                &token,
                t0 + Duration::hours(12) + Duration::minutes(1)
            )
            .is_none()
        );
    }
}
