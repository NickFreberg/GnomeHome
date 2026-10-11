"""Clients for the external feeds: NVD (CVEs), FIRST EPSS, and CISA KEV.

All network access goes through a small :class:`HttpClient` interface, so tests
use recorded responses and never touch the internet. The real client uses only
the standard library, with a timeout, retries with backoff, and a clear
User-Agent.

What leaves the house: NVD sees the CPE names being looked up (software and
versions, no device identifiers), and EPSS sees CVE IDs. Nothing else is sent.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Protocol

from gnomehome.cpe import CpeMatch

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
USER_AGENT = "GnomeHome/0.1 (home network risk scoring)"

#: NVD asks for at most 5 requests per 30 s without an API key, 50 with one.
NVD_PAUSE_NO_KEY = 6.5
NVD_PAUSE_WITH_KEY = 0.7
NVD_PAGE_SIZE = 2000
EPSS_BATCH = 50
# Order of preference: v3.1 is what most CVEs carry from NVD itself.
_CVSS_KEYS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2")


class FeedError(Exception):
    """A feed could not be fetched or understood."""


class HttpClient(Protocol):
    def get_json(self, url: str, *, headers: dict[str, str] | None = None) -> Any: ...


class UrllibClient:
    def __init__(
        self,
        *,
        timeout: float = 60,
        retries: int = 3,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.timeout = timeout
        self.retries = retries
        self.sleep = sleep

    def get_json(self, url: str, *, headers: dict[str, str] | None = None) -> Any:
        if not url.startswith("https://"):
            raise FeedError(f"refusing non-HTTPS URL: {url}")
        request = urllib.request.Request(  # noqa: S310 - checked above: https only
            url, headers={"User-Agent": USER_AGENT, **(headers or {})}
        )
        last: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                    return json.load(response)
            except urllib.error.HTTPError as exc:
                last = exc
                if exc.code not in (403, 429, 500, 502, 503, 504):
                    break
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                last = exc
            if attempt < self.retries:
                self.sleep(2 ** (attempt + 1))
        raise FeedError(f"GET {url.split('?')[0]} failed: {last}")


# --------------------------------------------------------------------------
# NVD
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class CveRecord:
    cve_id: str
    description: str | None
    published: str | None
    cvss_score: float | None
    cvss_version: str | None
    cvss_vector: str | None
    rules: tuple[CpeMatch, ...]


def pick_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    """Best available CVSS base score: newest common version, NVD's own ("Primary") first."""
    for key in _CVSS_KEYS:
        entries = [e for e in metrics.get(key, []) if isinstance(e.get("cvssData"), dict)]
        if not entries:
            continue
        entries.sort(key=lambda e: e.get("type") != "Primary")
        data = entries[0]["cvssData"]
        score = data.get("baseScore")
        if isinstance(score, int | float):
            return float(score), str(data.get("version", "")) or None, data.get("vectorString")
    return None, None, None


def parse_nvd_page(doc: dict[str, Any]) -> tuple[list[CveRecord], int]:
    records = []
    for item in doc.get("vulnerabilities", []):
        cve = item.get("cve") or {}
        cve_id = cve.get("id")
        if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
            continue
        if cve.get("vulnStatus") == "Rejected":
            continue
        description = next(
            (d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), None
        )
        score, version, vector = pick_cvss(cve.get("metrics") or {})
        rules = tuple(
            CpeMatch(
                criteria=match["criteria"],
                vulnerable=bool(match.get("vulnerable")),
                start_including=match.get("versionStartIncluding"),
                start_excluding=match.get("versionStartExcluding"),
                end_including=match.get("versionEndIncluding"),
                end_excluding=match.get("versionEndExcluding"),
            )
            for config in cve.get("configurations", [])
            for node in config.get("nodes", [])
            for match in node.get("cpeMatch", [])
            if isinstance(match.get("criteria"), str) and match["criteria"].startswith("cpe:2.3:")
        )
        records.append(
            CveRecord(
                cve_id,
                description,
                (cve.get("published") or "")[:10] or None,
                score,
                version,
                vector,
                rules,
            )
        )
    return records, int(doc.get("totalResults") or 0)


def fetch_nvd(
    client: HttpClient,
    cpe23: str,
    *,
    api_key: str | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> list[CveRecord]:
    """Every CVE NVD associates with this CPE (all pages), rejected ones excluded."""
    headers = {"apiKey": api_key} if api_key else {}
    pause = NVD_PAUSE_WITH_KEY if api_key else NVD_PAUSE_NO_KEY
    records: list[CveRecord] = []
    start = 0
    while True:
        query = urllib.parse.urlencode(
            {"virtualMatchString": cpe23, "resultsPerPage": NVD_PAGE_SIZE, "startIndex": start}
        )
        doc = client.get_json(f"{NVD_URL}?{query}&noRejected", headers=headers)
        page, total = parse_nvd_page(doc)
        records += page
        start += NVD_PAGE_SIZE
        sleep(pause)  # stay inside NVD's rate limit, also between pages
        if start >= total:
            return records


# --------------------------------------------------------------------------
# EPSS and KEV
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class EpssScore:
    epss: float
    percentile: float
    date: str


def fetch_epss(client: HttpClient, cve_ids: Iterable[str]) -> dict[str, EpssScore]:
    ids = sorted(set(cve_ids))
    scores: dict[str, EpssScore] = {}
    for i in range(0, len(ids), EPSS_BATCH):
        batch = ids[i : i + EPSS_BATCH]
        doc = client.get_json(f"{EPSS_URL}?{urllib.parse.urlencode({'cve': ','.join(batch)})}")
        for row in doc.get("data", []):
            try:
                scores[row["cve"]] = EpssScore(
                    float(row["epss"]), float(row["percentile"]), str(row["date"])
                )
            except (KeyError, TypeError, ValueError):
                continue
    return scores


@dataclass(frozen=True)
class KevEntry:
    cve_id: str
    vendor: str | None
    product: str | None
    name: str | None
    date_added: str | None
    due_date: str | None
    ransomware: bool


def fetch_kev(client: HttpClient) -> list[KevEntry]:
    doc = client.get_json(KEV_URL)
    entries = []
    for row in doc.get("vulnerabilities", []):
        cve_id = row.get("cveID")
        if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
            continue
        entries.append(
            KevEntry(
                cve_id=cve_id,
                vendor=row.get("vendorProject"),
                product=row.get("product"),
                name=(row.get("vulnerabilityName") or "").strip() or None,
                date_added=row.get("dateAdded"),
                due_date=row.get("dueDate"),
                ransomware=row.get("knownRansomwareCampaignUse") == "Known",
            )
        )
    if not entries:
        raise FeedError("KEV feed had no entries")
    return entries
