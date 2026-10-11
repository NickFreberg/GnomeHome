-- GnomeHome migration 0003: vulnerability enrichment and risk scoring (Phase 3).
--
-- Enrichment fetches CVEs from NVD per software version (CPE), stores each CVE's
-- "vulnerable configuration" rules, and then matches services against those
-- rules locally. Matching is repeatable and offline, and it is re-checked by our
-- own version logic rather than trusting NVD's broad search.

-- The CPE 2.3 name used for lookups (nmap reports CPE 2.2).
ALTER TABLE service ADD COLUMN cpe23 TEXT;
CREATE INDEX service_cpe23 ON service (cpe23);

ALTER TABLE cve ADD COLUMN kev_due_date TEXT;
ALTER TABLE cve ADD COLUMN kev_ransomware INTEGER CHECK (kev_ransomware IS NULL OR kev_ransomware IN (0, 1));

-- NVD configuration rules ("cpeMatch"), one row per rule per CVE.
CREATE TABLE cve_rule (
    id               INTEGER PRIMARY KEY,
    cve_id           TEXT    NOT NULL REFERENCES cve (cve_id) ON DELETE CASCADE,
    criteria         TEXT    NOT NULL CHECK (criteria GLOB 'cpe:2.3:*'),
    vulnerable       INTEGER NOT NULL CHECK (vulnerable IN (0, 1)),
    start_including  TEXT,
    start_excluding  TEXT,
    end_including    TEXT,
    end_excluding    TEXT
) STRICT;
CREATE INDEX cve_rule_cve ON cve_rule (cve_id);
CREATE INDEX cve_rule_criteria ON cve_rule (criteria);

-- When each CPE was last looked up at NVD, so lookups stay within the daily refresh.
CREATE TABLE nvd_lookup (
    cpe23      TEXT    PRIMARY KEY,
    fetched_at TEXT    NOT NULL CHECK (fetched_at GLOB '????-??-??T??:??:??.???Z'),
    cve_count  INTEGER NOT NULL CHECK (cve_count >= 0)
) STRICT;

-- The CISA Known Exploited Vulnerabilities catalog (about 1,700 rows).
CREATE TABLE kev_entry (
    cve_id     TEXT    PRIMARY KEY CHECK (cve_id GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*'),
    vendor     TEXT,
    product    TEXT,
    name       TEXT,
    date_added TEXT,
    due_date   TEXT,
    ransomware INTEGER NOT NULL DEFAULT 0 CHECK (ransomware IN (0, 1))
) STRICT;

-- Freshness of each external feed.
CREATE TABLE feed_status (
    feed       TEXT    PRIMARY KEY,
    fetched_at TEXT    NOT NULL CHECK (fetched_at GLOB '????-??-??T??:??:??.???Z'),
    items      INTEGER NOT NULL CHECK (items >= 0),
    detail     TEXT
) STRICT;

CREATE INDEX vulnerability_cve ON vulnerability (cve_id);
CREATE INDEX risk_score_date ON risk_score (score_date);
