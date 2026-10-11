"""The check-in job's entry point: ``python -m gnomehome.agent.run``.

Reads the summary for the week that ended yesterday, asks the model for a
check-in, validates it, writes ``reports/checkin/week_end=YYYY-MM-DD.json``, and
queues a ``weekly_checkin`` push. Settings come from environment variables that
``infra/modules/checkin.bicep`` sets on the job.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, date, datetime, timedelta
from typing import Any

from gnomehome.agent.azure import Azure, AzureError
from gnomehome.agent.prompt import RESPONSE_SCHEMA, InvalidOutput, build_messages, validate

REQUIRED = (
    "IDENTITY_ENDPOINT",
    "IDENTITY_HEADER",
    "AZURE_CLIENT_ID",
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_DEPLOYMENT",
    "GNOMEHOME_SUMMARIES_URL",
    "GNOMEHOME_REPORTS_URL",
)


def run_checkin(azure: Azure, env: dict[str, str], today: date) -> dict[str, Any]:
    week_end = (today - timedelta(days=1)).isoformat()
    summary_url = f"{env['GNOMEHOME_SUMMARIES_URL'].rstrip('/')}/week_end={week_end}.json"
    summary = json.loads(azure.read_blob(summary_url))
    raw = azure.chat(env["AZURE_OPENAI_ENDPOINT"], env["AZURE_OPENAI_DEPLOYMENT"],
                     build_messages(summary), RESPONSE_SCHEMA)  # fmt: skip
    result = validate(raw, summary)
    now = (
        datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.")
        + f"{datetime.now(UTC).microsecond // 1000:03d}Z"
    )
    report = {
        "schema": "gnomehome-checkin-v1",
        "week_end": week_end,
        "generated_at": now,
        "model_deployment": env["AZURE_OPENAI_DEPLOYMENT"],
        **result,
    }
    report_url = f"{env['GNOMEHOME_REPORTS_URL'].rstrip('/')}/week_end={week_end}.json"
    azure.write_blob(report_url, json.dumps(report, indent=2).encode())
    if env.get("GNOMEHOME_MONITOR_ENDPOINT") and env.get("GNOMEHOME_MONITOR_DCR_ID"):
        azure.push(
            env["GNOMEHOME_MONITOR_ENDPOINT"],
            env["GNOMEHOME_MONITOR_DCR_ID"],
            "weekly_checkin",
            now,
        )
    return report


def main() -> int:
    missing = [k for k in REQUIRED if not os.environ.get(k)]
    if missing:
        print(f"check-in: missing settings: {', '.join(missing)}", file=sys.stderr)
        return 2
    env = dict(os.environ)
    azure = Azure(env["IDENTITY_ENDPOINT"], env["IDENTITY_HEADER"], env["AZURE_CLIENT_ID"])
    try:
        report = run_checkin(azure, env, datetime.now(UTC).date())
    except (AzureError, InvalidOutput, json.JSONDecodeError) as exc:
        print(f"check-in failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"Check-in for the week ending {report['week_end']} written: "
        f"{len(report['suggestions'])} suggestion(s), {report['dropped_suggestions']} dropped."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
