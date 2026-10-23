"""The WiX download waits out a lost network and fails at once on anything a retry cannot fix."""

import hashlib
from pathlib import Path

import httpx
import pytest
from rich.console import Console
from tenacity import wait_none

import msi_installer
from msi_installer import BuildError, _download_and_hash, _download_file

BODY = b"wix-cli-x64 bytes"
BODY_SHA256 = hashlib.sha256(BODY).hexdigest()


@pytest.fixture(autouse=True)
def no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(msi_installer, "_DOWNLOAD_WAIT", wait_none())


def serve(monkeypatch: pytest.MonkeyPatch, responses: list) -> list[int]:
    """Answer successive requests from `responses`: an exception is raised, an int is a status code, bytes are a 200 body.

    Returns the list that records one entry per request made.
    """
    made: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        made.append(1)
        item = responses[min(len(made), len(responses)) - 1]
        if isinstance(item, Exception):
            raise item
        if isinstance(item, int):
            return httpx.Response(item)
        return httpx.Response(200, content=item)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(msi_installer.httpx, "stream", lambda method, url, **kw: client.stream(method, url))
    return made


def console() -> Console:
    return Console(quiet=True)


def test_a_lost_network_is_waited_out(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    made = serve(
        monkeypatch,
        [httpx.ConnectError("Temporary failure in name resolution"), httpx.ReadTimeout("slow"), BODY],
    )
    dest = tmp_path / "wix.msi"

    assert _download_and_hash("https://example.invalid/wix.msi", dest, console()) == BODY_SHA256
    assert len(made) == 3
    assert dest.read_bytes() == BODY


def test_a_server_error_is_retried(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    made = serve(monkeypatch, [503, 502, BODY])

    assert _download_and_hash("https://example.invalid/wix.msi", tmp_path / "wix.msi", console()) == BODY_SHA256
    assert len(made) == 3


def test_a_missing_file_is_not_retried(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    made = serve(monkeypatch, [404, BODY])

    with pytest.raises(httpx.HTTPStatusError):
        _download_and_hash("https://example.invalid/wix.msi", tmp_path / "wix.msi", console())
    assert len(made) == 1


def test_a_wrong_hash_of_a_complete_body_is_not_retried(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    made = serve(monkeypatch, [BODY, BODY])
    dest = tmp_path / "wix.msi"

    with pytest.raises(BuildError, match="SHA256 mismatch"):
        _download_file("https://example.invalid/wix.msi", dest, "0" * 64, console())
    assert len(made) == 1
    assert not dest.exists()
