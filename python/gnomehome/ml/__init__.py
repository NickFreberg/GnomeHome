"""Analytics and ML logic for Phase 6 (FR-12), in plain Python.

The Databricks jobs (``databricks/``) are thin wrappers: they read the Delta
tables, hand rows to these functions, and write the results back. Keeping the
logic here means it's tested in CI, runs the same on the Mac (``just ml``),
and needs no Spark to understand.

* ``features``: one row of behavior numbers per device per day
* ``anomaly``: robust z-scores against each device's own history
* ``classifier``: an explainable device-type guess from ports, vendor, OS, and DNS
"""
