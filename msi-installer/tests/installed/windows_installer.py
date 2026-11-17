"""The Windows Installer calls (`msi.dll`) the installed-Hole suite needs: which product an MSI is, which are installed,
and a property written into an MSI.

`msi.dll` is loaded inside each call so that importing this module on a non-Windows host (pytest collection) works.
"""

from __future__ import annotations

import ctypes
import xml.etree.ElementTree as ET
from contextlib import ExitStack
from ctypes import wintypes
from pathlib import Path

from conftest import WXS_PATH, find_package

_ERROR_NO_MORE_ITEMS = 259
_ERROR_MORE_DATA = 234
_MSIDBOPEN_TRANSACT = 1  # `MsiOpenDatabaseW`'s `szPersist`: changes are kept only by `MsiDatabaseCommit`
_VALUE_BUFFER_CHARS = 256
_GUID_BUFFER_CHARS = 39  # "{" + 36 + "}" + NUL


def _msi() -> ctypes.WinDLL:
    lib = ctypes.WinDLL("msi")
    for name in (
        "MsiOpenDatabaseW",
        "MsiDatabaseOpenViewW",
        "MsiViewExecute",
        "MsiViewFetch",
        "MsiViewClose",
        "MsiDatabaseCommit",
        "MsiCreateRecord",
        "MsiRecordSetStringW",
        "MsiRecordGetStringW",
    ):
        getattr(lib, name).restype = wintypes.UINT
    lib.MsiEnumRelatedProductsW.restype = wintypes.UINT
    return lib


def _check(code: int, call: str) -> None:
    if code != 0:
        raise OSError(f"{call} failed with Windows error {code}")


def _create_record(lib: ctypes.WinDLL, fields: int) -> int:
    handle = lib.MsiCreateRecord(fields)
    if not handle:
        raise OSError("MsiCreateRecord failed")
    return handle


def _record_string(lib: ctypes.WinDLL, record: wintypes.ULONG, field: int) -> str:
    buffer = ctypes.create_unicode_buffer(_VALUE_BUFFER_CHARS)
    size = wintypes.DWORD(_VALUE_BUFFER_CHARS)
    status = lib.MsiRecordGetStringW(record, field, buffer, ctypes.byref(size))
    if status == _ERROR_MORE_DATA:  # `size` now holds the length without the NUL
        buffer = ctypes.create_unicode_buffer(size.value + 1)
        size = wintypes.DWORD(size.value + 1)
        status = lib.MsiRecordGetStringW(record, field, buffer, ctypes.byref(size))
    _check(status, "MsiRecordGetStringW")
    return buffer.value


def _read_property(lib: ctypes.WinDLL, database: wintypes.ULONG, name: str) -> str | None:
    """The value of the `Property` row `name` in `database`, `None` without such a row."""
    with ExitStack() as handles:
        view, params, record = wintypes.ULONG(), _create_record(lib, 1), wintypes.ULONG()
        handles.callback(lib.MsiCloseHandle, params)
        _check(lib.MsiRecordSetStringW(params, 1, name), "MsiRecordSetStringW")
        query = "SELECT `Value` FROM `Property` WHERE `Property` = ?"
        _check(lib.MsiDatabaseOpenViewW(database, query, ctypes.byref(view)), "MsiDatabaseOpenViewW")
        handles.callback(lib.MsiCloseHandle, view)
        handles.callback(lib.MsiViewClose, view)  # runs before the handle is closed
        _check(lib.MsiViewExecute(view, params), "MsiViewExecute")
        status = lib.MsiViewFetch(view, ctypes.byref(record))
        if status == _ERROR_NO_MORE_ITEMS:
            return None
        _check(status, "MsiViewFetch")
        handles.callback(lib.MsiCloseHandle, record)
        return _record_string(lib, record, 1)


def _modify_property(lib: ctypes.WinDLL, database: wintypes.ULONG, query: str, *values: str) -> None:
    """Run the `INSERT` or `UPDATE` `query` on `database`, its `?` markers bound to `values`."""
    with ExitStack() as handles:
        view, params = wintypes.ULONG(), _create_record(lib, len(values))
        handles.callback(lib.MsiCloseHandle, params)
        for field, value in enumerate(values, start=1):
            _check(lib.MsiRecordSetStringW(params, field, value), "MsiRecordSetStringW")
        _check(lib.MsiDatabaseOpenViewW(database, query, ctypes.byref(view)), "MsiDatabaseOpenViewW")
        handles.callback(lib.MsiCloseHandle, view)
        handles.callback(lib.MsiViewClose, view)  # runs before the handle is closed
        _check(lib.MsiViewExecute(view, params), "MsiViewExecute")


def msi_property(msi: Path, name: str) -> str | None:
    """The value of the `Property` row `name` in `msi`, read from a fresh read-only open; `None` without such a row."""
    lib = _msi()
    with ExitStack() as handles:
        database = wintypes.ULONG()
        _check(lib.MsiOpenDatabaseW(str(msi), None, ctypes.byref(database)), "MsiOpenDatabaseW")
        handles.callback(lib.MsiCloseHandle, database)
        return _read_property(lib, database, name)


def msi_product_code(msi: Path) -> str:
    """The `{ProductCode}` in `msi`'s Property table. WiX makes a new one on every build."""
    code = msi_property(msi, "ProductCode")
    if code is None:
        raise OSError(f"{msi} has no ProductCode property")
    return code.upper()


def set_msi_property(msi: Path, name: str, value: str) -> None:
    """Set the `Property` row `name` of `msi` to `value` (inserted, or updated when it exists), and read it back.

    Edits the file itself: for a test input, never the shipped package. `MsiDatabaseCommit` writes the file; the
    database is then closed and the file opened again read-only, so a value that did not reach the disk raises
    `OSError` with the file already changed. Any earlier failure leaves the file unwritten.
    """
    lib = _msi()
    with ExitStack() as handles:
        database = wintypes.ULONG()
        transact = ctypes.c_void_p(_MSIDBOPEN_TRANSACT)
        _check(lib.MsiOpenDatabaseW(str(msi), transact, ctypes.byref(database)), "MsiOpenDatabaseW")
        handles.callback(lib.MsiCloseHandle, database)
        if _read_property(lib, database, name) is None:
            _modify_property(lib, database, "INSERT INTO `Property` (`Property`, `Value`) VALUES (?, ?)", name, value)
        else:
            _modify_property(lib, database, "UPDATE `Property` SET `Value` = ? WHERE `Property` = ?", value, name)
        _check(lib.MsiDatabaseCommit(database), "MsiDatabaseCommit")
    stored = msi_property(msi, name)
    if stored != value:
        raise OSError(f"{name} reads back as {stored!r} from {msi}, not {value!r}")


def related_product_codes(upgrade_code: str) -> list[str]:
    """The `{ProductCode}` of every installed product with this `{UpgradeCode}`."""
    lib = _msi()
    found = []
    index = 0
    while True:
        product = ctypes.create_unicode_buffer(_GUID_BUFFER_CHARS)
        status = lib.MsiEnumRelatedProductsW(upgrade_code, 0, index, product)
        if status == _ERROR_NO_MORE_ITEMS:
            return found
        _check(status, "MsiEnumRelatedProductsW")
        found.append(product.value.upper())
        index += 1


def hole_upgrade_code() -> str:
    package = find_package(ET.parse(WXS_PATH).getroot())
    return "{" + package.attrib["UpgradeCode"].upper() + "}"


def installed_hole_product_codes() -> list[str]:
    """The ProductCode of every Hole MSI installed on this machine, whichever build it came from."""
    return related_product_codes(hole_upgrade_code())
