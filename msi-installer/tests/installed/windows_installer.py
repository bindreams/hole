"""The Windows Installer calls (`msi.dll`) the installed-Hole suite needs: which product an MSI is, and which are installed.

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
_GUID_BUFFER_CHARS = 39  # "{" + 36 + "}" + NUL


def _msi() -> ctypes.WinDLL:
    lib = ctypes.WinDLL("msi")
    for name in ("MsiOpenDatabaseW", "MsiDatabaseOpenViewW", "MsiViewExecute", "MsiViewFetch", "MsiRecordGetStringW"):
        getattr(lib, name).restype = wintypes.UINT
    lib.MsiEnumRelatedProductsW.restype = wintypes.UINT
    return lib


def _check(code: int, call: str) -> None:
    if code != 0:
        raise OSError(f"{call} failed with Windows error {code}")


def msi_product_code(msi: Path) -> str:
    """The `{ProductCode}` in `msi`'s Property table. WiX makes a new one on every build."""
    lib = _msi()
    with ExitStack() as handles:
        database, view, record = wintypes.ULONG(), wintypes.ULONG(), wintypes.ULONG()
        _check(lib.MsiOpenDatabaseW(str(msi), None, ctypes.byref(database)), "MsiOpenDatabaseW")
        handles.callback(lib.MsiCloseHandle, database)
        query = "SELECT `Value` FROM `Property` WHERE `Property` = 'ProductCode'"
        _check(lib.MsiDatabaseOpenViewW(database, query, ctypes.byref(view)), "MsiDatabaseOpenViewW")
        handles.callback(lib.MsiCloseHandle, view)
        _check(lib.MsiViewExecute(view, 0), "MsiViewExecute")
        _check(lib.MsiViewFetch(view, ctypes.byref(record)), "MsiViewFetch")
        handles.callback(lib.MsiCloseHandle, record)
        size = wintypes.DWORD(_GUID_BUFFER_CHARS)
        code = ctypes.create_unicode_buffer(_GUID_BUFFER_CHARS)
        _check(lib.MsiRecordGetStringW(record, 1, code, ctypes.byref(size)), "MsiRecordGetStringW")
        return code.value.upper()


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
