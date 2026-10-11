"""Shared helpers for the GnomeHome Databricks jobs.

Every job takes two arguments, the storage account and the catalog, and gets
its Spark session the standard way. Paths follow infra/: the Pi uploads to
the ``raw`` container under ``gnomehome/``, and Unity Catalog keeps Delta
tables and checkpoints in ``lake``.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from pyspark.sql import SparkSession

TABLES = (
    "asset",
    "service",
    "vulnerability",
    "cve",
    "risk_score",
    "event",
    "incident",
    "audit_log",
)


@dataclass(frozen=True)
class Context:
    spark: SparkSession
    account: str
    catalog: str

    def raw(self, path: str = "") -> str:
        return f"abfss://raw@{self.account}.dfs.core.windows.net/gnomehome/{path}"

    def lake(self, path: str = "") -> str:
        return f"abfss://lake@{self.account}.dfs.core.windows.net/{path}"

    def table(self, schema: str, name: str) -> str:
        return f"{self.catalog}.{schema}.{name}"


def context() -> Context:
    if len(sys.argv) != 3:
        raise SystemExit("usage: <job>.py <storage account> <catalog>")
    spark = SparkSession.builder.getOrCreate()
    ctx = Context(spark, sys.argv[1], sys.argv[2])
    for schema in ("bronze", "silver", "gold"):
        spark.sql(f"CREATE SCHEMA IF NOT EXISTS {ctx.catalog}.{schema}")
    return ctx


def table_exists(ctx: Context, schema: str, name: str) -> bool:
    return ctx.spark.catalog.tableExists(ctx.table(schema, name))
