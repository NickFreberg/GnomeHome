"""The weekly summary for the AI check-in, built by ``gnomehome.summary``.

Written as ``gold.weekly_summary`` and as one JSON file per week in
``lake/gold/checkin/``, which the check-in job reads with a read-only identity.
Runs every night for the week ending yesterday, so the latest file is always fresh.
"""

from __future__ import annotations

import json
from datetime import date, timedelta

from common import context, table_exists
from pyspark.sql import functions as F

from gnomehome.summary import build_weekly_summary

ctx = context()
spark = ctx.spark


def collect(schema: str, name: str) -> list[dict]:
    return [r.asDict() for r in spark.table(ctx.table(schema, name)).collect()]


week_end = date.today() - timedelta(days=1)
start = (week_end - timedelta(days=6)).isoformat()
dns = (
    spark.table(ctx.table("silver", "event"))
    .where(
        (F.col("kind") == "dns")
        & (F.col("date") >= start)
        & (F.col("date") <= week_end.isoformat())
    )
    .agg(
        F.count("*").alias("queries"),
        F.sum(F.when(F.col("status") == "blocked", 1).otherwise(0)).alias("blocked"),
        F.countDistinct("src_ip").alias("devices"),
    )
    .first()
)
summary = build_weekly_summary(
    week_end=week_end,
    assets=collect("silver", "asset"),
    incidents=collect("silver", "incident"),
    risk_scores=[
        {**r, "summary": json.loads(r.get("factors") or "{}").get("summary")}
        for r in collect("silver", "risk_score")
    ],
    dns_totals={k: int(dns[k] or 0) for k in ("queries", "blocked", "devices")},
    anomalies=[
        {k: a[k] for k in ("device", "day", "severity", "reason")}
        for a in collect("gold", "anomaly")
        if start <= a["day"] <= week_end.isoformat()
    ],
    device_types={c["device"]: c["label"] for c in collect("gold", "device_type")},
)
text = json.dumps(summary, indent=2, ensure_ascii=False)
frame = spark.createDataFrame(
    [(week_end.isoformat(), text)], "week_end string, summary_json string"
)
target = ctx.table("gold", "weekly_summary")
if table_exists(ctx, "gold", "weekly_summary"):
    frame.write.mode("overwrite").option("replaceWhere", f"week_end = '{week_end}'").saveAsTable(
        target
    )
else:
    frame.write.saveAsTable(target)
dbutils = __import__("pyspark.dbutils", fromlist=["DBUtils"]).DBUtils(spark)
dbutils.fs.put(ctx.lake(f"gold/checkin/week_end={week_end.isoformat()}.json"), text, overwrite=True)
print(f"Weekly summary for the week ending {week_end} written.")
