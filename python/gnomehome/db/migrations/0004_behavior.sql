-- GnomeHome migration 0004: behavior monitoring (Phase 4).

-- Which domains each device has looked up, and since when. Drives "new domain
-- for this device" (FR-09) and separates new periodic behavior (possible
-- beaconing) from the baseline. Protected devices never appear: their queries
-- are dropped before storage, and the scrub removes any that predate the list.
CREATE TABLE device_domain (
    src_ip     TEXT    NOT NULL,
    domain     TEXT    NOT NULL,
    asset_id   INTEGER REFERENCES asset (id) ON DELETE CASCADE,
    first_seen TEXT    NOT NULL CHECK (first_seen GLOB '????-??-??T??:??:??.???Z'),
    last_seen  TEXT    NOT NULL CHECK (last_seen GLOB '????-??-??T??:??:??.???Z'),
    queries    INTEGER NOT NULL CHECK (queries >= 0),
    PRIMARY KEY (src_ip, domain)
) STRICT;
CREATE INDEX device_domain_first_seen ON device_domain (first_seen);

-- Known-bad domains from threat intel feeds (FR-10).
CREATE TABLE threat_indicator (
    indicator TEXT NOT NULL,
    kind      TEXT NOT NULL CHECK (kind IN ('domain')),
    source    TEXT NOT NULL,
    added_at  TEXT NOT NULL CHECK (added_at GLOB '????-??-??T??:??:??.???Z'),
    PRIMARY KEY (indicator, source)
) STRICT;
CREATE INDEX threat_indicator_indicator ON threat_indicator (indicator);

-- How far each detector has looked, so each run only examines new events.
CREATE TABLE analysis_checkpoint (
    detector TEXT PRIMARY KEY,
    last_ts  TEXT NOT NULL CHECK (last_ts GLOB '????-??-??T??:??:??.???Z')
) STRICT;

-- Connections currently open in the router's connection table (FR-08). When a
-- connection disappears from the table, it becomes one 'flow' event with totals.
CREATE TABLE conntrack_open (
    flow_key    TEXT    PRIMARY KEY,
    protocol    TEXT    NOT NULL,
    src_ip      TEXT    NOT NULL,
    src_port    INTEGER,
    dst_ip      TEXT    NOT NULL,
    dst_port    INTEGER,
    first_seen  TEXT    NOT NULL CHECK (first_seen GLOB '????-??-??T??:??:??.???Z'),
    last_seen   TEXT    NOT NULL CHECK (last_seen GLOB '????-??-??T??:??:??.???Z'),
    bytes_out   INTEGER NOT NULL DEFAULT 0,
    bytes_in    INTEGER NOT NULL DEFAULT 0,
    packets_out INTEGER NOT NULL DEFAULT 0,
    packets_in  INTEGER NOT NULL DEFAULT 0,
    state       TEXT
) STRICT;

CREATE INDEX event_dns_lookup ON event (kind, src_ip, domain, ts);
