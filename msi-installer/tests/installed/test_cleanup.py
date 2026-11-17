"""Uninstall what an interrupted lifecycle run left (a step timeout or Ctrl-C skips the fixture's teardown).

Run through `cargo xtask run hole-msi-cleanup`. Idempotent: on a machine with nothing installed it only checks that.
It uninstalls only a product the lifecycle suite recorded in its marker (`INSTALLED_MARKER`), by that ProductCode, so
a developer's own install is reported, never removed.
"""

import pytest
from support import (
    ensure_uninstalled,
    installed_suite_products,
    installed_traces,
    is_elevated,
    leftover_traces,
    log_dir,
    marker_path,
    read_marker,
)
from windows_installer import installed_hole_product_codes

pytestmark = pytest.mark.cleanup


def test_cleanup_leaves_nothing_installed():
    if not (traces := installed_traces()):
        marker_path().unlink(missing_ok=True)
        return
    found = f"Hole is installed ({'; '.join(traces)})"
    marker = read_marker()
    assert marker is not None, f"{found} but the suite did not install it: not uninstalling it"
    installed = installed_hole_product_codes()
    if not installed:
        leftovers = leftover_traces()
        assert not leftovers, (
            f"the suite's uninstall of {', '.join(marker.product_codes)} left: {'; '.join(leftovers)}. "
            "They cannot be removed without the product: remove them by hand"
        )
    if strangers := [code for code in installed if code not in marker.product_codes]:
        pytest.fail(
            f"{found}, but {', '.join(strangers)} is not a product the suite installed "
            f"({', '.join(marker.product_codes)}): not uninstalling it"
        )
    assert is_elevated(), "uninstalling needs an elevated shell"
    ensure_uninstalled(installed_suite_products(marker.product_codes), log_dir() / "msi-cleanup-uninstall.log")
    marker_path().unlink(missing_ok=True)
