-- GnomeHome migration 0007: dashboard accounts and sessions (Phase 8, NFR-01).
--
-- Local accounts only. Passwords are Argon2id hashes in PHC format; every login
-- also needs a TOTP code. Sessions are stored server-side: the browser holds a
-- random token, and only its SHA-256 is stored here, so a copy of the database
-- can't be used to log in. Every login and action is written to audit_log.

CREATE TABLE app_user (
    id              INTEGER PRIMARY KEY,
    username        TEXT    NOT NULL UNIQUE CHECK (username GLOB '[a-z]*' AND length(username) BETWEEN 2 AND 32),
    password_hash   TEXT    NOT NULL CHECK (password_hash GLOB '$argon2id$*'),
    role            TEXT    NOT NULL CHECK (role IN ('viewer', 'analyst', 'admin')),
    totp_secret     TEXT    NOT NULL,                 -- base32, 160 bits
    disabled        INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT    CHECK (locked_until IS NULL OR locked_until GLOB '????-??-??T??:??:??.???Z'),
    last_totp_step  INTEGER NOT NULL DEFAULT 0,       -- a code can't be used twice
    created_at      TEXT    NOT NULL CHECK (created_at GLOB '????-??-??T??:??:??.???Z')
) STRICT;

CREATE TABLE app_session (
    token_hash  TEXT    PRIMARY KEY,                  -- SHA-256 of the cookie value, hex
    user_id     INTEGER NOT NULL REFERENCES app_user (id) ON DELETE CASCADE,
    csrf_token  TEXT    NOT NULL,
    created_at  TEXT    NOT NULL CHECK (created_at GLOB '????-??-??T??:??:??.???Z'),
    last_seen   TEXT    NOT NULL CHECK (last_seen GLOB '????-??-??T??:??:??.???Z'),
    expires_at  TEXT    NOT NULL CHECK (expires_at GLOB '????-??-??T??:??:??.???Z'),
    mfa_at      TEXT    NOT NULL CHECK (mfa_at GLOB '????-??-??T??:??:??.???Z')   -- last TOTP check
) STRICT;

CREATE INDEX app_session_user ON app_session (user_id);
