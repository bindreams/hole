"""The WiX download waits out a lost network and fails at once on anything a retry cannot fix."""

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path

import httpx
import pytest
from rich.console import Console
from tenacity import wait_none

import msi_installer
from msi_installer import BuildError, _download_and_hash, _download_file


@dataclass
class CutShort:
    """A 200 response whose body delivers `prefix`, then fails with `error`: the network lost mid-download."""

    prefix: bytes
    error: Exception


BODY = b"wix-cli-x64 bytes"
BODY_SHA256 = hashlib.sha256(BODY).hexdigest()


@pytest.fixture(autouse=True)
def no_backoff(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Drop the backoff and record the pauses the retry loop asks for instead of sleeping them."""
    naps: list[float] = []
    monkeypatch.setattr(msi_installer, "_DOWNLOAD_WAIT", wait_none())
    monkeypatch.setattr(msi_installer, "_nap", naps.append)
    return naps


def serve(monkeypatch: pytest.MonkeyPatch, responses: list) -> list[int]:
    """Answer successive requests from `responses`: an exception is raised, an int is a status code, a (status, headers)
    pair is that status with those headers, bytes are a 200 body, a `CutShort` is a body that fails part-way.

    Returns the list that records one entry per request made.
    """
    made: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        made.append(1)
        item = responses[min(len(made), len(responses)) - 1]
        if isinstance(item, Exception):
            raise item
        if isinstance(item, CutShort):

            def body():
                yield item.prefix
                raise item.error

            return httpx.Response(200, content=body())
        if isinstance(item, tuple):
            status, headers = item
            return httpx.Response(status, headers=headers)
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


@pytest.mark.parametrize("status", [408, 429])
def test_a_request_to_try_again_is_retried(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, status: int) -> None:
    made = serve(monkeypatch, [status, status, BODY])

    assert _download_and_hash("https://example.invalid/wix.msi", tmp_path / "wix.msi", console()) == BODY_SHA256
    assert len(made) == 3


def test_the_wait_the_server_names_is_honoured(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, no_backoff: list[float]
) -> None:
    serve(monkeypatch, [(429, {"Retry-After": "7"}), BODY])

    _download_and_hash("https://example.invalid/wix.msi", tmp_path / "wix.msi", console())
    assert no_backoff == [7]


def test_a_wait_named_as_a_date_is_honoured(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, no_backoff: list[float]
) -> None:
    an_hour_on = format_datetime(datetime.now(timezone.utc) + timedelta(hours=1), usegmt=True)
    serve(monkeypatch, [(429, {"Retry-After": an_hour_on}), BODY])

    _download_and_hash("https://example.invalid/wix.msi", tmp_path / "wix.msi", console())
    # The date is whole seconds, so the wait is an hour less the time since it was formed.
    assert len(no_backoff) == 1 and 3590 < no_backoff[0] <= 3600


def test_a_date_is_read_against_the_given_time() -> None:
    response = httpx.Response(429, headers={"Retry-After": "Fri, 31 Dec 1999 23:59:59 GMT"})
    error = httpx.HTTPStatusError("429", request=httpx.Request("GET", "https://example.invalid"), response=response)
    thirty_s_before = datetime(1999, 12, 31, 23, 59, 29, tzinfo=timezone.utc)
    assert msi_installer._requested_wait(error, now=thirty_s_before) == 30
    assert msi_installer._requested_wait(error, now=thirty_s_before + timedelta(minutes=1)) == 0


@pytest.mark.parametrize("value", ["soon", "", "-5", "Fri, 99 Dec 1999 99:99:99 GMT"])
def test_a_wait_that_is_not_a_wait_falls_back_to_the_backoff(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, no_backoff: list[float], value: str
) -> None:
    serve(monkeypatch, [(429, {"Retry-After": value}), BODY])

    _download_and_hash("https://example.invalid/wix.msi", tmp_path / "wix.msi", console())
    assert no_backoff == [0]


@pytest.mark.parametrize(
    "error", [httpx.ReadError("connection reset"), httpx.RemoteProtocolError("peer closed connection")]
)
def test_a_network_lost_mid_body_is_waited_out(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, error: Exception
) -> None:
    made = serve(monkeypatch, [CutShort(b"wix-cli", error), CutShort(b"wix-cli-x64", error), BODY])
    dest = tmp_path / "wix.msi"

    # The hash covers the final body alone, not the bytes of the attempts that were cut short.
    assert _download_and_hash("https://example.invalid/wix.msi", dest, console()) == BODY_SHA256
    assert len(made) == 3
    assert dest.read_bytes() == BODY
    assert not dest.with_suffix(".tmp").exists()


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
