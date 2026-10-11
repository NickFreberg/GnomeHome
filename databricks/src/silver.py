"""Silver: verify each day, then clean and deduplicate it.

A day is used only when its manifest says the protected-asset guard checked
every row and every file matches its SHA-256 (``gnomehome.export.verify_partition``).
The audit log's hash chain is recomputed (``gnomehome.audit``) and must end at
the hash the Pi recorded. Any problem fails the job, which stops the pipeline
before gold and Power BI.

The protected list itself never leaves the Pi, so there's no identifier check
here: rows about protected devices were dropped before export.
"""

from __future__ import annotations

import json
import re

from common import context, table_exists
from pyspark.sql import Window
from pyspark.sql import functions as F

from gnomehome.audit import GENESIS_HASH, compute_hash
from gnomehome.export import verify_partition

ctx = context()
spark = ctx.spark

verified = (
    {r.date for r in spark.table(ctx.table("silver", "verified_day")).collect()}
    if table_exists(ctx, "silver", "verified_day")
    else set()
)
manifests = [
    r for r in spark.table(ctx.table("bronze", "manifest")).collect() if r.date not in verified
]

problems: dict[str, list[str]] = {}
new_days = []
for row in sorted(manifests, key=lambda r: r.date):
    manifest = json.loads(row.manifest_json)

    def read(path: str) -> bytes:
        return spark.read.format("binaryFile").load(ctx.raw(path)).first().content

    found = verify_partition(manifest, read)
    if found:
        problems[row.date] = found
    else:
        new_days.append((row.date, manifest))

if problems:
    raise RuntimeError(f"export verification failed: {json.dumps(problems)}")

# Recompute the audit log's hash chain across the new days.
last = (
    spark.table(ctx.table("silver", "audit_log")).orderBy(F.desc("seq")).first()
    if table_exists(ctx, "silver", "audit_log")
    else None
)
prev_hash, expected_seq = (last.hash, last.seq + 1) if last else (GENESIS_HASH, None)
for day, manifest in new_days:
    rows = (
        spark.table(ctx.table("bronze", "audit_log"))
        .where(F.col("date") == day)
        .orderBy("seq")
        .collect()
    )
    for r in rows:
        if expected_seq is not None and r.seq != expected_seq:
            raise RuntimeError(f"audit log gap on {day}: expected seq {expected_seq}, got {r.seq}")
        digest = compute_hash(
            seq=r.seq, ts=r.ts, actor=r.actor, action=r.action, target=r.target,
            result=r.result, details=r.details, prev_hash=r.prev_hash,
        )  # fmt: skip
        if r.prev_hash != prev_hash or digest != r.hash:
            raise RuntimeError(f"audit log hash chain broken at seq {r.seq} ({day})")
        prev_hash, expected_seq = r.hash, r.seq + 1
    # The manifest records the chain's head at export time. When that's the last entry
    # exported, the recomputed chain must end on exactly that hash.
    head = manifest.get("audit_head")
    if head and rows and head["seq"] == rows[-1].seq and head["hash"] != prev_hash:
        raise RuntimeError(f"audit log for {day} doesn't end at the hash the Pi recorded")

if not new_days:
    print("No new verified days.")
    raise SystemExit(0)

days = [d for d, _ in new_days]
if not all(re.fullmatch(r"\d{4}-\d{2}-\d{2}", d) for d in days):
    raise RuntimeError(f"unexpected partition names: {days}")
in_days = "date IN (" + ", ".join(f"'{d}'" for d in days) + ")"


def latest_by(name: str, key: str, order: str) -> None:
    """Keep the newest version of each row (snapshots and changing rows)."""
    df = spark.table(ctx.table("bronze", name))
    newest = Window.partitionBy(key).orderBy(F.desc(order), F.desc("date"))
    latest = df.withColumn("_n", F.row_number().over(newest)).where("_n = 1")
    (
        latest.drop("_n", "_rescued_data")
        .write.mode("overwrite")
        .option("overwriteSchema", "true")
        .saveAsTable(ctx.table("silver", name))
    )


for name, key, order in (
    ("asset", "id", "last_seen"),
    ("service", "id", "last_seen"),
    ("vulnerability", "id", "last_seen"),
    ("cve", "cve_id", "updated_at"),
    ("incident", "id", "updated_at"),
    ("risk_score", "id", "computed_at"),
):
    latest_by(name, key, order)

# Events and audit entries are append-only: replace just the new days.
for name in ("event", "audit_log"):
    df = (
        spark.table(ctx.table("bronze", name)).where(F.col("date").isin(days))
        .withColumn("ts", F.to_timestamp("ts")).drop("_rescued_data")
        .dropDuplicates(["seq"] if name == "audit_log" else ["id"])
    )  # fmt: skip
    if table_exists(ctx, "silver", name):
        df.write.mode("overwrite").option("replaceWhere", in_days).saveAsTable(
            ctx.table("silver", name)
        )
    else:
        df.write.partitionBy("date").saveAsTable(ctx.table("silver", name))

spark.createDataFrame([(d,) for d in days], "date string").withColumn(
    "verified_at", F.current_timestamp()
).write.mode("append").saveAsTable(ctx.table("silver", "verified_day"))
print(f"Verified and loaded {len(days)} day(s): {', '.join(days)}")
