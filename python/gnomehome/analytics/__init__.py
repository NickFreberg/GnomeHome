"""DNS behavior analytics (Phase 4, FR-09 and FR-10).

These run as a scheduled job over events already in SQLite. They send nothing
and touch no device. Protected devices' queries never reach the database, so
they can't appear here. Domain names come from devices and are untrusted: they
are only measured and quoted, never interpreted.
"""
