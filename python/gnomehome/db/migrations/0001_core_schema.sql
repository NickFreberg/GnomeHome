-- GnomeHome core schema (migration 0001).
--
-- SQLite in WAL mode is the contract between the Python jobs and the Rust
-- services. Python applies migrations (gnomehome.db.migrate); Rust only
-- checks the schema version. Never edit this file once applied anywhere:
-- add 0002_*.sql instead (the migrator refuses edited migrations).
--
-- Conventions
--   * STRICT tables: SQLite enforces column types.
--   * Timestamps: UTC, fixed width, '2026-10-11T14:03:00.000Z' (text order = time order).
--   * MACs: lowercase, colon separated, two digits per octet.
--   * Text that comes from devices (hostnames, banners, DNS names) is untrusted.
--     Store it via bound parameters only; never interpret it.
--
-- Protected assets (plan, "Protected assets", step 7): a protected device
-- may only be recorded as present, with no further detail. The CHECK on
-- asset and the triggers at the bottom enforce that here, so the Rust side
-- inherits the rule even before it has its own guard.

-- ---------------------------------------------------------------------------
-- Scan runs: one row per discovery or service scan.
-- ---------------------------------------------------------------------------
CREATE TABLE scan_run (
    id            INTEGER PRIMARY KEY,
    kind          TEXT    NOT NULL CHECK (kind IN ('discovery', 'service')),
    started_at    TEXT    NOT NULL CHECK (started_at GLOB '????-??-??T??:??:??.???Z'),
    finished_at   TEXT             CHECK (finished_at IS NULL OR finished_at GLOB '????-??-??T??:??:??.???Z'),
    status        TEXT    NOT NULL CHECK (status IN ('running', 'success', 'failed', 'aborted')),
    targets       TEXT    NOT NULL CHECK (json_valid(targets)),
    nmap_version  TEXT,
    hosts_up      INTEGER CHECK (hosts_up IS NULL OR hosts_up >= 0),
    assets_new    INTEGER CHECK (assets_new IS NULL OR assets_new >= 0),
    services_seen INTEGER CHECK (services_seen IS NULL OR services_seen >= 0),
    error         TEXT
) STRICT;

-- ---------------------------------------------------------------------------
-- Asset: one per MAC.
-- ---------------------------------------------------------------------------
CREATE TABLE asset (
    id             INTEGER PRIMARY KEY,
    mac            TEXT    NOT NULL UNIQUE
                   CHECK (mac GLOB '[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]'),
    protected      INTEGER NOT NULL DEFAULT 0 CHECK (protected IN (0, 1)),
    -- Locally administered bit set: likely a phone's randomized MAC, so one
    -- device may appear as several assets (known data quality issue).
    mac_randomized INTEGER NOT NULL DEFAULT 0 CHECK (mac_randomized IN (0, 1)),
    device_type    TEXT,
    vendor         TEXT,
    hostname       TEXT,
    last_ip        TEXT,
    os_guess       TEXT,
    os_accuracy    INTEGER CHECK (os_accuracy IS NULL OR os_accuracy BETWEEN 0 AND 100),
    first_seen     TEXT    NOT NULL CHECK (first_seen GLOB '????-??-??T??:??:??.???Z'),
    last_seen      TEXT    NOT NULL CHECK (last_seen GLOB '????-??-??T??:??:??.???Z'),
    last_scan_id   INTEGER REFERENCES scan_run (id) ON DELETE SET NULL,
    CHECK (last_seen >= first_seen),
    -- A protected device records existence only.
    CHECK (protected = 0 OR (
        device_type IS NULL AND vendor IS NULL AND hostname IS NULL AND last_ip IS NULL
        AND os_guess IS NULL AND os_accuracy IS NULL AND last_scan_id IS NULL
    ))
) STRICT;

CREATE INDEX asset_last_ip ON asset (last_ip);

-- ---------------------------------------------------------------------------
-- Service: one per asset, port, and protocol, mapped to a CPE.
-- ---------------------------------------------------------------------------
CREATE TABLE service (
    id           INTEGER PRIMARY KEY,
    asset_id     INTEGER NOT NULL REFERENCES asset (id) ON DELETE CASCADE,
    port         INTEGER NOT NULL CHECK (port BETWEEN 0 AND 65535),
    protocol     TEXT    NOT NULL CHECK (protocol IN ('tcp', 'udp', 'sctp')),
    state        TEXT    NOT NULL,
    name         TEXT,
    product      TEXT,
    version      TEXT,
    extra_info   TEXT,
    -- As reported by nmap (CPE 2.2 URI, e.g. 'cpe:/a:vendor:product:1.0').
    -- Phase 3 maps it to CPE 2.3 for NVD lookups.
    cpe          TEXT,
    first_seen   TEXT    NOT NULL CHECK (first_seen GLOB '????-??-??T??:??:??.???Z'),
    last_seen    TEXT    NOT NULL CHECK (last_seen GLOB '????-??-??T??:??:??.???Z'),
    last_scan_id INTEGER REFERENCES scan_run (id) ON DELETE SET NULL,
    UNIQUE (asset_id, port, protocol)
) STRICT;

-- ---------------------------------------------------------------------------
-- Vulnerability: a CVE linked to a service. CVE facts (CVSS, EPSS, KEV) live
-- once per CVE in `cve`, so the daily EPSS refresh updates one row per CVE.
-- ---------------------------------------------------------------------------
CREATE TABLE cve (
    cve_id          TEXT PRIMARY KEY CHECK (cve_id GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*'),
    description     TEXT,
    published       TEXT,
    cvss_score      REAL CHECK (cvss_score IS NULL OR cvss_score BETWEEN 0 AND 10),
    cvss_version    TEXT,
    cvss_vector     TEXT,
    epss            REAL CHECK (epss IS NULL OR epss BETWEEN 0 AND 1),
    epss_percentile REAL CHECK (epss_percentile IS NULL OR epss_percentile BETWEEN 0 AND 1),
    epss_date       TEXT,
    kev             INTEGER NOT NULL DEFAULT 0 CHECK (kev IN (0, 1)),
    kev_date_added  TEXT,
    updated_at      TEXT NOT NULL CHECK (updated_at GLOB '????-??-??T??:??:??.???Z')
) STRICT;

CREATE TABLE vulnerability (
    id           INTEGER PRIMARY KEY,
    service_id   INTEGER NOT NULL REFERENCES service (id) ON DELETE CASCADE,
    cve_id       TEXT    NOT NULL REFERENCES cve (cve_id) ON DELETE CASCADE,
    match_method TEXT    NOT NULL CHECK (match_method IN ('cpe_exact', 'cpe_version_range', 'manual')),
    confidence   REAL    CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 1),
    first_seen   TEXT    NOT NULL CHECK (first_seen GLOB '????-??-??T??:??:??.???Z'),
    last_seen    TEXT    NOT NULL CHECK (last_seen GLOB '????-??-??T??:??:??.???Z'),
    UNIQUE (service_id, cve_id)
) STRICT;

-- ---------------------------------------------------------------------------
-- Risk score: one per asset per day. `factors` explains the score.
-- Levels match the design system's risk scale.
-- ---------------------------------------------------------------------------
CREATE TABLE risk_score (
    id            INTEGER PRIMARY KEY,
    asset_id      INTEGER NOT NULL REFERENCES asset (id) ON DELETE CASCADE,
    score_date    TEXT    NOT NULL CHECK (score_date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    score         REAL    NOT NULL CHECK (score BETWEEN 0 AND 100),
    level         TEXT    NOT NULL CHECK (level IN ('low', 'medium', 'high', 'critical')),
    factors       TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(factors)),
    model_version TEXT    NOT NULL,
    computed_at   TEXT    NOT NULL CHECK (computed_at GLOB '????-??-??T??:??:??.???Z'),
    UNIQUE (asset_id, score_date)
) STRICT;

-- ---------------------------------------------------------------------------
-- Event: a DNS query, flow, syslog line, or DHCP record tied to an asset.
-- Protected devices' events are dropped by the guard before they get here.
-- ---------------------------------------------------------------------------
CREATE TABLE event (
    id          INTEGER PRIMARY KEY,
    ts          TEXT    NOT NULL CHECK (ts GLOB '????-??-??T??:??:??.???Z'),
    kind        TEXT    NOT NULL CHECK (kind IN ('dns', 'flow', 'syslog', 'dhcp')),
    source      TEXT    NOT NULL,              -- 'pihole', 'router', 'synthetic', ...
    synthetic   INTEGER NOT NULL DEFAULT 0 CHECK (synthetic IN (0, 1)),
    asset_id    INTEGER REFERENCES asset (id) ON DELETE CASCADE,
    src_ip      TEXT,
    src_port    INTEGER CHECK (src_port IS NULL OR src_port BETWEEN 0 AND 65535),
    dst_ip      TEXT,
    dst_port    INTEGER CHECK (dst_port IS NULL OR dst_port BETWEEN 0 AND 65535),
    protocol    TEXT,
    domain      TEXT,                          -- DNS: queried name (untrusted)
    query_type  TEXT,                          -- DNS: A, AAAA, HTTPS, ...
    status      TEXT,                          -- DNS: allowed/blocked; flow: conntrack state
    bytes_out   INTEGER CHECK (bytes_out IS NULL OR bytes_out >= 0),
    bytes_in    INTEGER CHECK (bytes_in IS NULL OR bytes_in >= 0),
    packets_out INTEGER CHECK (packets_out IS NULL OR packets_out >= 0),
    packets_in  INTEGER CHECK (packets_in IS NULL OR packets_in >= 0),
    message     TEXT,                          -- syslog: the raw line (untrusted)
    attrs       TEXT    CHECK (attrs IS NULL OR json_valid(attrs)),
    CHECK (kind <> 'dns' OR (domain IS NOT NULL AND src_ip IS NOT NULL)),
    CHECK (kind <> 'flow' OR (src_ip IS NOT NULL AND dst_ip IS NOT NULL AND protocol IS NOT NULL)),
    CHECK (kind <> 'syslog' OR message IS NOT NULL)
) STRICT;

CREATE INDEX event_kind_ts ON event (kind, ts);
CREATE INDEX event_asset_ts ON event (asset_id, ts);
CREATE INDEX event_src_ip_ts ON event (src_ip, ts);

-- ---------------------------------------------------------------------------
-- Incident: a detection with its plain-English summary, playbook run, and outcome.
-- ---------------------------------------------------------------------------
CREATE TABLE incident (
    id              INTEGER PRIMARY KEY,
    created_at      TEXT NOT NULL CHECK (created_at GLOB '????-??-??T??:??:??.???Z'),
    updated_at      TEXT NOT NULL CHECK (updated_at GLOB '????-??-??T??:??:??.???Z'),
    asset_id        INTEGER REFERENCES asset (id) ON DELETE CASCADE,
    detection       TEXT NOT NULL,                       -- e.g. 'dns.beaconing'
    severity        TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    confidence      REAL CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 1),
    title           TEXT NOT NULL,
    summary         TEXT NOT NULL,                       -- what happened and why it matters
    mitre_technique TEXT CHECK (mitre_technique IS NULL OR mitre_technique GLOB 'T[0-9][0-9][0-9][0-9]*'),
    status          TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'pending_approval', 'acknowledged', 'resolved', 'false_positive')),
    playbook        TEXT,
    playbook_run_id TEXT,
    tier            TEXT CHECK (tier IS NULL OR tier IN ('auto_act', 'ask_first', 'scheduled')),
    outcome         TEXT,
    evidence        TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(evidence))
) STRICT;

CREATE INDEX incident_asset ON incident (asset_id);

-- ---------------------------------------------------------------------------
-- Audit log: append-only and hash-chained (spec: docs/audit-log.md).
-- SQLite can't compute SHA-256, so the hash itself is verified by
-- `just audit-verify`. The schema does enforce append-only, contiguous
-- sequence numbers, and prev_hash linking to the previous row.
-- ---------------------------------------------------------------------------
CREATE TABLE audit_log (
    seq       INTEGER PRIMARY KEY,
    ts        TEXT NOT NULL CHECK (ts GLOB '????-??-??T??:??:??.???Z'),
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    target    TEXT,
    result    TEXT NOT NULL CHECK (result IN ('success', 'failure', 'refused')),
    details   TEXT CHECK (details IS NULL OR json_valid(details)),
    prev_hash TEXT NOT NULL CHECK (length(prev_hash) = 64 AND prev_hash NOT GLOB '*[^0-9a-f]*'),
    hash      TEXT NOT NULL UNIQUE CHECK (length(hash) = 64 AND hash NOT GLOB '*[^0-9a-f]*')
) STRICT;

CREATE TRIGGER audit_log_chain BEFORE INSERT ON audit_log
WHEN NEW.seq IS NOT COALESCE((SELECT MAX(seq) FROM audit_log), 0) + 1
  OR NEW.prev_hash IS NOT COALESCE(
       (SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1),
       '0000000000000000000000000000000000000000000000000000000000000000')
BEGIN
    SELECT RAISE(ABORT, 'audit_log: seq must be the next number and prev_hash must match the last row');
END;

CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

-- ---------------------------------------------------------------------------
-- Protected-asset enforcement.
-- ---------------------------------------------------------------------------
CREATE TRIGGER service_refuse_protected BEFORE INSERT ON service
WHEN (SELECT protected FROM asset WHERE id = NEW.asset_id) = 1
BEGIN
    SELECT RAISE(ABORT, 'protected asset: services may not be stored');
END;

CREATE TRIGGER service_refuse_protected_move BEFORE UPDATE OF asset_id ON service
WHEN (SELECT protected FROM asset WHERE id = NEW.asset_id) = 1
BEGIN
    SELECT RAISE(ABORT, 'protected asset: services may not be stored');
END;

CREATE TRIGGER event_refuse_protected BEFORE INSERT ON event
WHEN (SELECT protected FROM asset WHERE id = NEW.asset_id) = 1
BEGIN
    SELECT RAISE(ABORT, 'protected asset: events may not be stored');
END;

CREATE TRIGGER event_refuse_protected_move BEFORE UPDATE OF asset_id ON event
WHEN (SELECT protected FROM asset WHERE id = NEW.asset_id) = 1
BEGIN
    SELECT RAISE(ABORT, 'protected asset: events may not be stored');
END;

CREATE TRIGGER risk_score_refuse_protected BEFORE INSERT ON risk_score
WHEN (SELECT protected FROM asset WHERE id = NEW.asset_id) = 1
BEGIN
    SELECT RAISE(ABORT, 'protected asset: risk scores may not be stored');
END;

CREATE TRIGGER risk_score_refuse_protected_move BEFORE UPDATE OF asset_id ON risk_score
WHEN (SELECT protected FROM asset WHERE id = NEW.asset_id) = 1
BEGIN
    SELECT RAISE(ABORT, 'protected asset: risk scores may not be stored');
END;

CREATE TRIGGER incident_refuse_protected BEFORE INSERT ON incident
WHEN (SELECT protected FROM asset WHERE id = NEW.asset_id) = 1
BEGIN
    SELECT RAISE(ABORT, 'protected asset: incidents may not be stored');
END;

CREATE TRIGGER incident_refuse_protected_move BEFORE UPDATE OF asset_id ON incident
WHEN (SELECT protected FROM asset WHERE id = NEW.asset_id) = 1
BEGIN
    SELECT RAISE(ABORT, 'protected asset: incidents may not be stored');
END;

-- When a device is added to the protected list after it was already scanned,
-- marking it protected deletes everything stored about it.
CREATE TRIGGER asset_became_protected AFTER UPDATE OF protected ON asset
WHEN NEW.protected = 1 AND OLD.protected = 0
BEGIN
    DELETE FROM service WHERE asset_id = NEW.id;
    DELETE FROM event WHERE asset_id = NEW.id;
    DELETE FROM risk_score WHERE asset_id = NEW.id;
    DELETE FROM incident WHERE asset_id = NEW.id;
END;
