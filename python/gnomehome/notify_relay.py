"""Deliver queued notifications (FR-16): ``just notify``, every minute on the Pi.

The playbook engine and the weekly assessment queue a notification *kind* in
``notification_outbox``, never free text. This relay turns each kind into a
fixed message, so no device name, domain, or address can reach a lock screen:

* locally, through the existing notifier (the journal on the Pi, a banner on
  the Mac)
* in Azure, when ``[cloud]`` names a Logs Ingestion endpoint: it sends only
  ``{TimeGenerated, Kind}`` to a custom table, and one Azure Monitor alert rule
  (``infra/modules/notifications.bicep``) pushes to the Azure mobile app

Azure sign-in uses an app registration's client secret from a file outside git
(``monitor_secret_file``); the app holds only "Monitoring Metrics Publisher" on
one data collection rule. The secret is never printed.
"""

from __future__ import annotations

import json
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from gnomehome.alerts import Notifier
from gnomehome.db import transaction
from gnomehome.timeutil import utc_now

MESSAGES = {
    "approval_needed": "A response is waiting for your approval. Run `just approvals`.",
    "action_taken": "GnomeHome took a response action. Run `just incidents` for details.",
    "action_failed": "A response action failed. Run `just incidents` for details.",
    "weekly_assessment": "Your weekly self-assessment is ready. Run `just incidents`.",
}
STREAM = "Custom-GnomeHomeNotify_CL"
API_VERSION = "2023-01-01"


class RelayError(Exception):
    """Azure refused the notification or couldn't be reached. They stay queued."""


@dataclass
class AzureMonitor:
    """Logs Ingestion API client (client-credentials sign-in, standard library only)."""

    tenant_id: str
    client_id: str
    secret: str = field(repr=False)
    endpoint: str
    dcr_id: str
    opener: Callable[..., object] = urllib.request.urlopen
    timeout: float = 30

    def _post(self, url: str, data: bytes, headers: dict[str, str]) -> bytes:
        if not url.startswith("https://"):
            raise RelayError("Azure endpoints must be https")
        request = urllib.request.Request(url, data=data, method="POST", headers=headers)  # noqa: S310
        try:
            with self.opener(request, timeout=self.timeout) as response:  # type: ignore[attr-defined]
                return response.read()
        except urllib.error.HTTPError as exc:
            raise RelayError(f"Azure returned HTTP {exc.code}") from None
        except urllib.error.URLError as exc:
            raise RelayError(f"Azure unreachable: {exc.reason}") from None

    def _token(self) -> str:
        body = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.secret,
                "scope": "https://monitor.azure.com//.default",
            }
        ).encode()
        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        reply = json.loads(
            self._post(url, body, {"Content-Type": "application/x-www-form-urlencoded"})
        )
        token = reply.get("access_token")
        if not token:
            raise RelayError("Azure sign-in returned no token")
        return token

    def send(self, kinds: list[tuple[str, str]]) -> None:
        """``kinds`` is ``[(created_at, kind), ...]``. Only those two fields leave the Pi."""
        token = self._token()
        rows = [{"TimeGenerated": ts, "Kind": kind} for ts, kind in kinds]
        url = (
            f"{self.endpoint.rstrip('/')}/dataCollectionRules/{self.dcr_id}/streams/{STREAM}"
            f"?api-version={API_VERSION}"
        )
        self._post(
            url,
            json.dumps(rows).encode(),
            {"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )


def load_secret(path: Path) -> str:
    try:
        if path.stat().st_mode & 0o004:
            raise RelayError(f"{path} is readable by every user: chmod 0640 it")
        secret = path.read_text().strip()
    except OSError as exc:
        raise RelayError(f"can't read {path}: {exc.strerror}") from None
    if not secret:
        raise RelayError(f"{path} is empty")
    return secret


@dataclass
class RelayResult:
    sent: int = 0
    azure: bool = False


def relay(
    conn: sqlite3.Connection, notifier: Notifier, azure: AzureMonitor | None = None
) -> RelayResult:
    """Deliver every pending notification. On an Azure failure, nothing is marked sent."""
    pending = conn.execute(
        "SELECT id, kind, created_at FROM notification_outbox WHERE status = 'pending' ORDER BY id"
    ).fetchall()
    result = RelayResult(azure=azure is not None)
    if not pending:
        return result
    if azure is not None:
        azure.send([(row["created_at"], row["kind"]) for row in pending])
    # One local message per kind, however many are queued.
    for kind in dict.fromkeys(row["kind"] for row in pending):
        notifier.notify(MESSAGES[kind])
    now = utc_now()
    # Marked sent only after delivery, in one short write (no network call holds the lock).
    with transaction(conn):
        conn.executemany(
            "UPDATE notification_outbox SET status = 'sent', sent_at = ? WHERE id = ?",
            [(now, row["id"]) for row in pending],
        )
    result.sent = len(pending)
    return result
