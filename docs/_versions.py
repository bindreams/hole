"""Release-group versions, read from their own manifests.

Shared by `docs/conf.py`, which renders them as MyST substitutions, and
`scripts/validate-docs.py`, which checks that they rendered. One definition of
which release groups exist, so a fifth one cannot be added to the docs while the
validator keeps checking four.
"""
import tomllib
from pathlib import Path

# MyST substitution names.
SUBSTITUTIONS = ("hole_version", "galoshes_version", "garter_version", "exray_version")


def manifest_versions(root: Path) -> dict[str, str]:
    """Substitution name -> version. Raises rather than yielding a blank version."""
    versions = {
        f"{crate}_version": _manifest_version(root / "crates" / crate / "Cargo.toml", "package")
        for crate in ("hole", "galoshes", "garter")
    }
    # ex-ray is a Go crate with no Cargo manifest, so its version sits at the top level.
    versions["exray_version"] = _manifest_version(root / "crates" / "ex-ray" / "version.toml")
    return versions


def _manifest_version(manifest: Path, *tables: str) -> str:
    with manifest.open("rb") as f:
        data = tomllib.load(f)
    for table in tables:
        data = data[table]

    version = data["version"]
    if not isinstance(version, str):
        raise TypeError(f"{manifest}: version is {type(version).__name__}, not str -- it needs quoting")
    return version
