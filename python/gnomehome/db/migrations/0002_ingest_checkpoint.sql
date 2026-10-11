-- GnomeHome migration 0002: incremental log ingestion and incident lookups.
--
-- ingest_checkpoint remembers how far each log file has been read, so each
-- run reads only new lines. The job saves the new offset in the same
-- transaction as the events it stored, so a crash or rerun never duplicates
-- or skips lines. If the file's inode changes or it shrinks (log rotation),
-- reading restarts at the beginning of the new file.

CREATE TABLE ingest_checkpoint (
    source      TEXT    PRIMARY KEY,             -- e.g. 'router_syslog'
    path        TEXT    NOT NULL,
    inode       INTEGER NOT NULL,
    byte_offset INTEGER NOT NULL CHECK (byte_offset >= 0),
    updated_at  TEXT    NOT NULL CHECK (updated_at GLOB '????-??-??T??:??:??.???Z')
) STRICT;

-- Deduplicating alerts looks up open incidents by detection type.
CREATE INDEX incident_detection_status ON incident (detection, status);
