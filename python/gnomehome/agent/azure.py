"""Azure calls for the check-in job, standard library only.

The Container Apps job signs in with its managed identity (no keys or secrets):
the platform sets ``IDENTITY_ENDPOINT`` and ``IDENTITY_HEADER``, and
``AZURE_CLIENT_ID`` picks the user-assigned identity from ``infra/``.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

OPENAI_API_VERSION = "2024-10-21"
STORAGE_VERSION = "2023-11-03"


class AzureError(Exception):
    """An Azure call failed. Messages never include tokens."""


@dataclass
class Azure:
    identity_endpoint: str
    identity_header: str = field(repr=False)
    client_id: str
    opener: Callable[..., Any] = urllib.request.urlopen
    timeout: float = 60
    _tokens: dict[str, str] = field(default_factory=dict, repr=False)

    def _send(self, request: urllib.request.Request) -> bytes:
        try:
            with self.opener(request, timeout=self.timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            raise AzureError(
                f"{request.get_method()} {_host(request.full_url)}: HTTP {exc.code}"
            ) from None
        except urllib.error.URLError as exc:
            raise AzureError(f"{_host(request.full_url)} unreachable: {exc.reason}") from None

    def token(self, resource: str) -> str:
        if resource not in self._tokens:
            query = urllib.parse.urlencode(
                {"resource": resource, "api-version": "2019-08-01", "client_id": self.client_id}
            )
            request = urllib.request.Request(  # noqa: S310 (the platform's local identity endpoint)
                f"{self.identity_endpoint}?{query}",
                headers={"X-IDENTITY-HEADER": self.identity_header},
            )
            reply = json.loads(self._send(request))
            if not reply.get("access_token"):
                raise AzureError("the managed identity returned no token")
            self._tokens[resource] = reply["access_token"]
        return self._tokens[resource]

    def _https(self, method: str, url: str, resource: str, body: bytes | None = None,
               headers: dict[str, str] | None = None) -> bytes:  # fmt: skip
        if not url.startswith("https://"):
            raise AzureError("Azure URLs must be https")
        all_headers = {"Authorization": f"Bearer {self.token(resource)}", **(headers or {})}
        request = urllib.request.Request(  # noqa: S310 (https checked above)
            url, data=body, method=method, headers=all_headers
        )
        return self._send(request)

    def read_blob(self, url: str) -> bytes:
        return self._https(
            "GET", url, "https://storage.azure.com", headers={"x-ms-version": STORAGE_VERSION}
        )

    def write_blob(self, url: str, data: bytes) -> None:
        self._https("PUT", url, "https://storage.azure.com", data, {
            "x-ms-version": STORAGE_VERSION, "x-ms-blob-type": "BlockBlob",
            "Content-Type": "application/json"})  # fmt: skip

    def chat(self, endpoint: str, deployment: str, messages: list[dict[str, str]],
             schema: dict[str, Any]) -> str:  # fmt: skip
        url = (
            f"{endpoint.rstrip('/')}/openai/deployments/{urllib.parse.quote(deployment)}"
            f"/chat/completions?api-version={OPENAI_API_VERSION}"
        )
        body = {
            "messages": messages,
            "temperature": 0.2,
            "max_tokens": 1500,
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "checkin", "strict": True, "schema": schema},
            },
        }
        reply = json.loads(self._https("POST", url, "https://cognitiveservices.azure.com",
                                       json.dumps(body).encode(),
                                       {"Content-Type": "application/json"}))  # fmt: skip
        try:
            return reply["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise AzureError("the model returned no message") from None

    def push(self, endpoint: str, dcr_id: str, kind: str, ts: str) -> None:
        url = (
            f"{endpoint.rstrip('/')}/dataCollectionRules/{dcr_id}/streams/Custom-GnomeHomeNotify_CL"
            "?api-version=2023-01-01"
        )
        rows = json.dumps([{"TimeGenerated": ts, "Kind": kind}]).encode()
        self._https(
            "POST", url, "https://monitor.azure.com", rows, {"Content-Type": "application/json"}
        )


def _host(url: str) -> str:
    return urllib.parse.urlsplit(url).hostname or "Azure"
