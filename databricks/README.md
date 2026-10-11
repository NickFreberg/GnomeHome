# databricks: the nightly analytics pipeline (Phase 6)

A [Databricks Asset Bundle](https://learn.microsoft.com/en-us/azure/databricks/dev-tools/bundles/) that turns
the Pi's nightly export into Delta tables, runs the ML, and writes the weekly summary the AI check-in reads.

> **Status: written, not deployed.** pyspark isn't available in CI, so the five job files have only been
> compiled and linted. Everything they import from the `gnomehome` package is tested
> (`python/tests/test_ml.py`, `test_cloud_logic.py`), and a test checks that every such import exists.
> Expect small fixes on the first run.

## The pipeline

One job, `gnomehome-nightly`, at 04:30 UTC (after the Pi's export). Serverless compute only, so nothing
bills while idle. Each task waits for the one before it, so a failure stops the run before anything
downstream, including Power BI, sees half-processed data.

| Task | Reads | Writes | Logic |
| --- | --- | --- | --- |
| `bronze` | `raw/gnomehome/<table>/date=…/*.jsonl.gz`, `raw/gnomehome/_manifests/` | `bronze.<table>`, `bronze.manifest` | Auto Loader: only new files, unchanged |
| `silver` | bronze | `silver.<table>`, `silver.verified_day` | Each day must pass `gnomehome.export.verify_partition` (guard-checked flag, SHA-256 of every file). The audit log's hash chain is recomputed with `gnomehome.audit` and must end on the hash the Pi recorded. Then deduplicate and type |
| `gold` | `silver.event` | `gold.device_day`, `gold.device_domain` | `gnomehome.ml.features`, one day at a time |
| `ml` | gold, silver | `gold.anomaly`, `gold.device_type` | `gnomehome.ml.anomaly` and `gnomehome.ml.classifier` |
| `summary` | silver, gold | `gold.weekly_summary`, `lake/gold/checkin/week_end=….json` | `gnomehome.summary` (the same function as `just summary` on the Pi) |

The jobs install the `gnomehome` package as a wheel, so the cloud runs exactly the code the Pi and the tests
run. Try the logic locally first: `just ml --dev` and `just summary --dev`.

**The protected-asset list never leaves the Pi.** Silver can't re-check identifiers, because that would
mean storing the work laptop's MACs in Azure. Instead, every day must carry the Pi's `guard_checked`
manifest and match its checksums.

## Deploy (after `infra/`)

1. Install the Databricks CLI on the Mac: `brew tap databricks/tap && brew install databricks`.
2. Log in: `databricks auth login --host <databricksUrl from the infra outputs>`.
3. Put the workspace URL in `databricks.yml` (both targets), then:

```
cd databricks
databricks bundle validate -t dev --var storage_account=<account> --var alert_email=<you>
databricks bundle deploy   -t dev --var storage_account=<account> --var alert_email=<you>
databricks bundle run gnomehome_nightly -t dev --var storage_account=<account> --var alert_email=<you>
```

`dev` mode prefixes everything with your name and pauses the schedule. Use `-t prod` when it works.

## Power BI

Connect Power BI Desktop to the serverless SQL warehouse (**Get data**, then **Azure Databricks**, then the
warehouse's server hostname and HTTP path) and use the `gnomehome.gold` tables. Refreshes read gold only, so a
failed nightly run leaves yesterday's numbers in place.
