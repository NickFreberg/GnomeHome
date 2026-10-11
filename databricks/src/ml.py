"""ML: unusual days (``gold.anomaly``) and device-type guesses (``gold.device_type``).

Both run the Pi's tested code (``gnomehome.ml``) on small tables collected to
the driver: a few hundred device-days, and one profile per device.
"""

from __future__ import annotations

from dataclasses import asdict

from common import context
from pyspark.sql import functions as F

from gnomehome.ml.anomaly import detect
from gnomehome.ml.classifier import classify, profiles_from_rows
from gnomehome.ml.features import FEATURES, DeviceDay, fill_missing_days

ctx = context()
spark = ctx.spark

rows = spark.table(ctx.table("gold", "device_day")).collect()
days = fill_missing_days(
    [DeviceDay(r.device, r.day, {name: r[name] for name in FEATURES}) for r in rows]
)
anomalies = [asdict(a) for a in detect(days)]
schema = (
    "device string, day string, feature string, value double, baseline double, z double, "
    "severity string, reason string"
)
spark.createDataFrame(anomalies, schema).write.mode("overwrite").saveAsTable(
    ctx.table("gold", "anomaly")
)

recent = spark.table(ctx.table("silver", "event")).where(
    (F.col("kind") == "dns") & (F.col("ts") >= F.date_sub(F.current_date(), 14))
)
profiles = profiles_from_rows(
    [r.asDict() for r in spark.table(ctx.table("silver", "asset")).collect()],
    [r.asDict() for r in spark.table(ctx.table("silver", "service")).collect()],
    [r.asDict() for r in recent.select("src_ip", "domain").toLocalIterator()],
)
results = [classify(p) for p in profiles]
spark.createDataFrame(
    [(c.device, c.label, float(c.confidence), list(c.evidence)) for c in results],
    "device string, label string, confidence double, evidence array<string>",
).write.mode("overwrite").saveAsTable(ctx.table("gold", "device_type"))
print(f"{len(anomalies)} anomaly(ies), {len(results)} device(s) classified")
