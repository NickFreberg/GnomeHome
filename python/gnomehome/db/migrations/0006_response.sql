-- GnomeHome migration 0006: response and the automated Blue Team (Phase 7).
--
-- The Rust playbook engine (crates/gnomehome-playbook) writes these tables.
-- Protected devices can never be the target of a run or a quarantine: the
-- triggers below refuse it, on top of the guard check in the engine.

-- One playbook execution for one incident (or one scheduled run).
CREATE TABLE playbook_run (
    id           TEXT    PRIMARY KEY,                    -- random hex
    playbook     TEXT    NOT NULL,
    version      INTEGER NOT NULL,
    incident_id  INTEGER REFERENCES incident (id) ON DELETE SET NULL,
    asset_id     INTEGER REFERENCES asset (id) ON DELETE SET NULL,
    tier         TEXT    NOT NULL CHECK (tier IN ('auto_act', 'ask_first', 'scheduled')),
    status       TEXT    NOT NULL CHECK (status IN (
                     'running', 'awaiting_approval', 'approved', 'denied', 'expired',
                     'skipped', 'refused', 'succeeded', 'failed')),
    dry_run      INTEGER NOT NULL CHECK (dry_run IN (0, 1)),
    started_at   TEXT    NOT NULL CHECK (started_at GLOB '????-??-??T??:??:??.???Z'),
    finished_at  TEXT    CHECK (finished_at IS NULL OR finished_at GLOB '????-??-??T??:??:??.???Z'),
    outcome      TEXT                                    -- plain English, label only for protected devices
) STRICT;

CREATE INDEX playbook_run_status ON playbook_run (status);
CREATE INDEX playbook_run_incident ON playbook_run (incident_id);

-- Each detect, enrich, decide, act, and report step of a run.
CREATE TABLE playbook_step (
    id      INTEGER PRIMARY KEY,
    run_id  TEXT    NOT NULL REFERENCES playbook_run (id) ON DELETE CASCADE,
    seq     INTEGER NOT NULL,
    phase   TEXT    NOT NULL CHECK (phase IN ('detect', 'enrich', 'decide', 'act', 'report', 'release')),
    action  TEXT,
    status  TEXT    NOT NULL CHECK (status IN ('ok', 'dry_run', 'skipped', 'refused', 'failed')),
    detail  TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(detail)),
    at      TEXT    NOT NULL CHECK (at GLOB '????-??-??T??:??:??.???Z'),
    UNIQUE (run_id, seq)
) STRICT;

-- Ask-first actions wait here for the owner (FR-16): approve or deny in the
-- dashboard or with `just approve`. Unanswered requests expire.
CREATE TABLE approval (
    id           INTEGER PRIMARY KEY,
    run_id       TEXT    NOT NULL UNIQUE REFERENCES playbook_run (id) ON DELETE CASCADE,
    requested_at TEXT    NOT NULL CHECK (requested_at GLOB '????-??-??T??:??:??.???Z'),
    expires_at   TEXT    NOT NULL CHECK (expires_at GLOB '????-??-??T??:??:??.???Z'),
    decision     TEXT    CHECK (decision IS NULL OR decision IN ('approved', 'denied', 'expired')),
    decided_at   TEXT    CHECK (decided_at IS NULL OR decided_at GLOB '????-??-??T??:??:??.???Z'),
    decided_by   TEXT,
    CHECK ((decision IS NULL) = (decided_at IS NULL))
) STRICT;

-- Push notifications waiting for the relay. Only a fixed kind is stored, never
-- free text: the relay maps each kind to a fixed message, so no device name,
-- domain, or address can ever reach a phone's lock screen.
CREATE TABLE notification_outbox (
    id          INTEGER PRIMARY KEY,
    kind        TEXT    NOT NULL CHECK (kind IN (
                    'approval_needed', 'action_taken', 'action_failed', 'weekly_assessment')),
    incident_id INTEGER REFERENCES incident (id) ON DELETE SET NULL,
    created_at  TEXT    NOT NULL CHECK (created_at GLOB '????-??-??T??:??:??.???Z'),
    status      TEXT    NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed')),
    sent_at     TEXT    CHECK (sent_at IS NULL OR sent_at GLOB '????-??-??T??:??:??.???Z')
) STRICT;

CREATE INDEX notification_outbox_status ON notification_outbox (status);

-- Temporary actions, so they can be listed, released on time, and undone.
CREATE TABLE response_action (
    id          INTEGER PRIMARY KEY,
    run_id      TEXT    NOT NULL REFERENCES playbook_run (id) ON DELETE CASCADE,
    kind        TEXT    NOT NULL CHECK (kind IN ('pihole_block', 'router_quarantine')),
    target      TEXT    NOT NULL,          -- a domain, or a non-protected device's MAC
    asset_id    INTEGER REFERENCES asset (id) ON DELETE SET NULL,
    dry_run     INTEGER NOT NULL CHECK (dry_run IN (0, 1)),
    started_at  TEXT    NOT NULL CHECK (started_at GLOB '????-??-??T??:??:??.???Z'),
    expires_at  TEXT    NOT NULL CHECK (expires_at GLOB '????-??-??T??:??:??.???Z'),
    released_at TEXT    CHECK (released_at IS NULL OR released_at GLOB '????-??-??T??:??:??.???Z')
) STRICT;

CREATE INDEX response_action_open ON response_action (released_at, expires_at);

CREATE TRIGGER playbook_run_refuse_protected BEFORE INSERT ON playbook_run
WHEN (SELECT protected FROM asset WHERE id = NEW.asset_id) = 1
BEGIN
    SELECT RAISE(ABORT, 'protected asset: playbooks may not target it');
END;

CREATE TRIGGER playbook_run_refuse_protected_move BEFORE UPDATE OF asset_id ON playbook_run
WHEN (SELECT protected FROM asset WHERE id = NEW.asset_id) = 1
BEGIN
    SELECT RAISE(ABORT, 'protected asset: playbooks may not target it');
END;

CREATE TRIGGER response_action_refuse_protected BEFORE INSERT ON response_action
WHEN (SELECT protected FROM asset WHERE id = NEW.asset_id) = 1
  OR (NEW.kind = 'router_quarantine' AND EXISTS (
        SELECT 1 FROM asset WHERE protected = 1 AND mac = NEW.target))
BEGIN
    SELECT RAISE(ABORT, 'protected asset: it may not be quarantined');
END;

-- A device added to the protected list later loses its response history too.
-- (A router rule from an earlier quarantine lasts only until the router reboots.)
CREATE TRIGGER asset_became_protected_response AFTER UPDATE OF protected ON asset
WHEN NEW.protected = 1 AND OLD.protected = 0
BEGIN
    DELETE FROM response_action WHERE asset_id = NEW.id OR target = NEW.mac;
    DELETE FROM playbook_run WHERE asset_id = NEW.id;
END;
