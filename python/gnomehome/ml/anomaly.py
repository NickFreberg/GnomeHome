"""Anomaly detection: each device compared with its own normal (FR-12).

For every device-day and feature, the detector computes a *robust z-score*:
how far today's value sits from the median of the device's other days,
measured in MADs (median absolute deviations), the version Iglewicz and
Hoaglin recommend. Medians ignore the odd spike in the history, so one
strange day doesn't hide the next one, and nothing needs training.

* Only rises are flagged: an upload ten times bigger than usual matters,
  a quiet day mostly doesn't.
* Each feature has a minimum spread, so a device that always sends exactly
  zero bytes doesn't raise an alarm over one byte. The spread is also at least
  a quarter of the usual value, so a streaming stick that downloads 60 GB one
  day and 90 GB the next isn't news.
* A device needs ``min_history`` earlier days before it can be judged.

The output says, in words, what was unusual and by how much.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass

from gnomehome.ml.features import FEATURES, DeviceDay

#: The smallest spread a feature can have, in its own units.
MIN_SCALE: dict[str, float] = {
    "dns_queries": 50.0,
    "distinct_domains": 10.0,
    "nxdomain_share": 0.05,
    "blocked_share": 0.05,
    "new_domains": 10.0,
    "night_share": 0.05,
    "flows": 25.0,
    "bytes_out": 20e6,
    "bytes_in": 100e6,
    "distinct_destinations": 10.0,
    "dns_bypass_flows": 5.0,
}

THRESHOLD = 3.5  # Iglewicz and Hoaglin's cutoff for an outlier
HIGH = 8.0
RELATIVE_SCALE = 0.25


@dataclass(frozen=True)
class Anomaly:
    device: str
    day: str
    feature: str
    value: float
    baseline: float
    z: float
    severity: str
    reason: str


def robust_z(value: float, history: list[float], min_scale: float) -> tuple[float, float]:
    """``(z, median)``. 1.4826 x MAD estimates the standard deviation for normal data."""
    median = statistics.median(history)
    mad = statistics.median(abs(v - median) for v in history)
    scale = max(1.4826 * mad, min_scale, RELATIVE_SCALE * abs(median))
    return (value - median) / scale, median


def detect(
    days: list[DeviceDay],
    *,
    window: int = 28,
    min_history: int = 5,
    threshold: float = THRESHOLD,
    leave_one_out: bool = False,
) -> list[Anomaly]:
    """Score every device-day.

    By default each day is compared with the ``window`` days before it, which is
    how the nightly job runs. ``leave_one_out`` compares each day with all the
    device's other days instead, for scoring a backfill in one pass.
    """
    by_device: dict[str, list[DeviceDay]] = defaultdict(list)
    for d in days:
        by_device[d.device].append(d)
    found = []
    for device, rows in sorted(by_device.items()):
        rows.sort(key=lambda r: r.day)
        for i, target in enumerate(rows):
            history = rows[:i] + rows[i + 1 :] if leave_one_out else rows[max(0, i - window) : i]
            if len(history) < min_history:
                continue
            for feature, label in FEATURES.items():
                value = target.values.get(feature, 0.0)
                past = [h.values.get(feature, 0.0) for h in history]
                z, median = robust_z(value, past, MIN_SCALE[feature])
                if z < threshold:
                    continue
                found.append(
                    Anomaly(
                        device=device,
                        day=target.day,
                        feature=feature,
                        value=value,
                        baseline=median,
                        z=round(z, 1),
                        severity="high" if z >= HIGH else "medium",
                        reason=_reason(feature, label, value, median),
                    )
                )
    return found


def _reason(feature: str, label: str, value: float, median: float) -> str:
    def fmt(v: float) -> str:
        if feature.endswith("_share"):
            return f"{v:.0%}"
        if feature.startswith("bytes"):
            return _bytes(v)
        return f"{v:,.0f}"

    ratio = (
        f", about {value / median:,.0f} times as much" if median > 0 and value / median >= 2 else ""
    )
    return f"{label.capitalize()}: {fmt(value)}, against a usual {fmt(median)}{ratio}."


def _bytes(n: float) -> str:
    for unit in ("bytes", "KB", "MB", "GB"):
        if n < 1000 or unit == "GB":
            return f"{n:,.0f} {unit}" if unit == "bytes" else f"{n:,.1f} {unit}"
        n /= 1000
    return f"{n:,.1f} GB"
