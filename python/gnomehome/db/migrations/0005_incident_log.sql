-- GnomeHome migration 0005: the plain-English incident log (FR-11).
--
-- Each incident keeps its story in parts, so the incident report, the
-- dashboard, and the weekly check-in can show them separately. `summary`
-- (from 0001) still holds the parts joined into one paragraph.
--
--   occurred_at     when the activity happened (created_at is when it was detected)
--   device          who it's about, in words. Protected devices appear by label only.
--   what_happened   the facts, with device-supplied text quoted and labeled
--   why_it_matters  the risk, in plain words
--   next_steps      what the owner can do about it

ALTER TABLE incident ADD COLUMN occurred_at TEXT
    CHECK (occurred_at IS NULL OR occurred_at GLOB '????-??-??T??:??:??.???Z');
ALTER TABLE incident ADD COLUMN device TEXT;
ALTER TABLE incident ADD COLUMN what_happened TEXT;
ALTER TABLE incident ADD COLUMN why_it_matters TEXT;
ALTER TABLE incident ADD COLUMN next_steps TEXT;

CREATE INDEX incident_occurred ON incident (occurred_at);
