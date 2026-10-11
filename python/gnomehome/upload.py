"""Upload an exported day to Azure Data Lake Storage Gen2 (Phase 6).

Uses the Blob service's ``Put Blob`` call with a SAS token, which works on
ADLS Gen2 accounts. The token comes from a file (``storage_sas_file``) and
should be a *service SAS* on the one container, tied to a stored access
policy, with create and write permission only: the Pi can add files but
can't read, list, or delete anything, and deleting the policy revokes it.
``infra/README.md`` shows how to make one.

Dry run is the default. ``--send`` uploads. The token is never printed or
logged, and error messages never include the URL.
"""

from __future__ import annotations

import stat
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from gnomehome.export import partition_files

API_VERSION = "2023-11-03"
CONTENT_TYPES = {".gz": "application/gzip", ".json": "application/json"}


class UploadError(Exception):
    """The upload isn't configured correctly, or the storage account refused it."""


def load_sas(path: Path, *, allow_read: bool = False) -> str:
    """A SAS token from a file. Upload tokens must not read or delete; the check-in
    fetch passes ``allow_read`` for its read-only token, which must not write."""
    try:
        mode = path.stat().st_mode
        token = path.read_text().strip().removeprefix("?")
    except OSError as exc:
        raise UploadError(f"can't read the SAS token file {path}: {exc.strerror}") from None
    if mode & (stat.S_IROTH | stat.S_IWOTH):
        raise UploadError(
            f"{path} is readable by every user: chmod 0640 it (owner root, group gnomehome)"
        )
    fields = urllib.parse.parse_qs(token)
    if not {"sv", "sig"} <= set(fields):
        raise UploadError(f"{path} doesn't look like a SAS token (it needs sv= and sig=)")
    permissions = fields.get("sp", [""])[0]
    if allow_read:
        if any(p in permissions for p in "wcd"):
            raise UploadError("the reports token can write or delete: make one with read only")
    elif "r" in permissions or "d" in permissions:
        raise UploadError(
            "the SAS token allows reading or deleting: make one with create and write only"
        )
    return token


@dataclass
class BlobClient:
    account: str
    container: str
    sas: str = field(repr=False)
    opener: Callable[..., object] = urllib.request.urlopen
    timeout: float = 120

    def url(self, blob: str) -> str:
        path = urllib.parse.quote(f"{self.container}/{blob}")
        return f"https://{self.account}.blob.core.windows.net/{path}?{self.sas}"

    def put(self, blob: str, data: bytes, content_type: str) -> None:
        request = urllib.request.Request(  # noqa: S310 (https only, built above)
            self.url(blob),
            data=data,
            method="PUT",
            headers={
                "x-ms-blob-type": "BlockBlob",
                "x-ms-version": API_VERSION,
                "Content-Type": content_type,
            },
        )
        try:
            with self.opener(request, timeout=self.timeout) as response:  # type: ignore[attr-defined]
                if response.status not in (200, 201):
                    raise UploadError(f"upload of {blob} failed with HTTP {response.status}")
        except urllib.error.HTTPError as exc:
            raise UploadError(f"upload of {blob} failed with HTTP {exc.code}") from None
        except urllib.error.URLError as exc:
            raise UploadError(f"upload of {blob} failed: {exc.reason}") from None


def plan_uploads(out_dir: Path, day: str, prefix: str) -> list[tuple[Path, str]]:
    """``(local file, blob name)`` pairs, data first and the manifest last."""
    return [
        (path, f"{prefix}/{path.relative_to(out_dir).as_posix()}")
        for path in partition_files(out_dir, day)
    ]


def upload_day(client: BlobClient, out_dir: Path, day: str, prefix: str) -> list[str]:
    """Upload every file for ``day``. The manifest goes last, so its presence means complete."""
    plan = plan_uploads(out_dir, day, prefix)
    if not plan or not plan[-1][0].name.endswith(".json"):
        raise UploadError(f"no complete export for {day} in {out_dir}: run `just export` first")
    for path, blob in plan:
        client.put(
            blob, path.read_bytes(), CONTENT_TYPES.get(path.suffix, "application/octet-stream")
        )
    return [blob for _, blob in plan]
