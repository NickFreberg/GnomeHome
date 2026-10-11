"""Bronze: land the Pi's nightly files as Delta tables, unchanged.

Auto Loader picks up only files it hasn't seen, so a rerun is harmless. The
``date=YYYY-MM-DD`` folder becomes a ``date`` column. Manifests land in
``bronze.manifest`` so silver can check every day before trusting it.
"""

from __future__ import annotations

from common import TABLES, context
from pyspark.sql import functions as F

ctx = context()

for name in TABLES:
    (
        ctx.spark.readStream.format("cloudFiles")
        .option("cloudFiles.format", "json")
        .option("cloudFiles.inferColumnTypes", "true")
        .option("cloudFiles.partitionColumns", "date")
        .option("cloudFiles.schemaLocation", ctx.lake(f"_checkpoints/bronze/{name}/schema"))
        .load(ctx.raw(f"{name}/"))
        .withColumn("_source_file", F.col("_metadata.file_path"))
        .withColumn("_ingested_at", F.current_timestamp())
        .writeStream.option("checkpointLocation", ctx.lake(f"_checkpoints/bronze/{name}/data"))
        .option("mergeSchema", "true")
        .trigger(availableNow=True)
        .toTable(ctx.table("bronze", name))
        .awaitTermination()
    )

(
    ctx.spark.readStream.format("cloudFiles")
    .option("cloudFiles.format", "text")
    .option("wholetext", "true")
    .option("cloudFiles.schemaLocation", ctx.lake("_checkpoints/bronze/manifest/schema"))
    .load(ctx.raw("_manifests/"))
    .select(
        F.regexp_extract(F.col("_metadata.file_path"), r"date=(\d{4}-\d{2}-\d{2})", 1).alias(
            "date"
        ),
        F.col("value").alias("manifest_json"),
        F.current_timestamp().alias("_ingested_at"),
    )
    .writeStream.option("checkpointLocation", ctx.lake("_checkpoints/bronze/manifest/data"))
    .trigger(availableNow=True)
    .toTable(ctx.table("bronze", "manifest"))
    .awaitTermination()
)
