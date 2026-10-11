"""Gold: one row of behavior features per device per day (``gold.device_day``).

Runs the same ``gnomehome.ml.features`` code as the Pi, one day at a time, so
only a day's events are ever collected to the driver (tens of thousands of
rows for a household). ``gold.device_domain`` remembers which domains each
device already knew, so "new domains" stays accurate across runs.
"""

from __future__ import annotations

from collections import defaultdict

from common import context, table_exists
from pyspark.sql import functions as F

from gnomehome.analytics.domains import registered_domain
from gnomehome.ml.features import FEATURES, daily_features

ctx = context()
spark = ctx.spark

days = sorted(
    r.date
    for r in spark.table(ctx.table("silver", "verified_day")).select("date").distinct().collect()
)
done = (
    {r.day for r in spark.table(ctx.table("gold", "device_day")).select("day").distinct().collect()}
    if table_exists(ctx, "gold", "device_day")
    else set()
)
known: dict[str, set[str]] = defaultdict(set)
if table_exists(ctx, "gold", "device_domain"):
    for r in spark.table(ctx.table("gold", "device_domain")).collect():
        known[r.device].add(r.domain)

events = spark.table(ctx.table("silver", "event"))
for day in [d for d in days if d not in done]:
    rows = (
        events.where((F.col("date") == day) & F.col("kind").isin("dns", "flow"))
        .select("kind", F.date_format("ts", "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").alias("ts"), "src_ip",
                "dst_ip", "dst_port", "domain", "status", "bytes_out", "bytes_in")
        .toLocalIterator()
    )  # fmt: skip
    dns, flows = [], []
    for r in rows:
        (dns if r.kind == "dns" else flows).append(r.asDict())
    before = {device: set(domains) for device, domains in known.items()}
    features = daily_features(dns, flows, known_domains=before)
    if features:
        spark.createDataFrame(
            [{"device": f.device, "day": f.day, **f.values} for f in features],
            "device string, day string, " + ", ".join(f"{name} double" for name in FEATURES),
        ).write.mode("append").saveAsTable(ctx.table("gold", "device_day"))
    new_pairs = set()
    for q in dns:
        domain = registered_domain(q["domain"])
        if domain not in known[q["src_ip"]]:
            known[q["src_ip"]].add(domain)
            new_pairs.add((q["src_ip"], domain, day))
    if new_pairs:
        spark.createDataFrame(
            sorted(new_pairs), "device string, domain string, first_day string"
        ).write.mode("append").saveAsTable(ctx.table("gold", "device_domain"))
    print(f"{day}: {len(features)} device-day row(s)")
