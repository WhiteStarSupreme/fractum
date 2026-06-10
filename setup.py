import hashlib
import sys
from pathlib import Path

from setuptools import find_packages, setup

from src.config import REQUIRED_PYTHON_VERSION, VERSION


def _verify_package_checksums(packages_dir: Path) -> None:
    """L1: verify bundled .whl files against known-good SHA-256 hashes.

    Raises SystemExit if any .whl is missing from CHECKSUMS.sha256 or has
    a hash that does not match — this protects against a tampered local copy
    going undetected at install time.
    """
    checksums_file = packages_dir / "CHECKSUMS.sha256"
    if not checksums_file.exists():
        print(
            "ERROR: packages/CHECKSUMS.sha256 not found. "
            "Cannot verify bundled .whl integrity.",
            file=sys.stderr,
        )
        sys.exit(1)

    expected: dict = {}
    for line in checksums_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            digest, name = parts
            expected[name.strip()] = digest.strip()

    for whl in packages_dir.glob("*.whl"):
        if whl.name not in expected:
            print(
                f"ERROR: {whl.name} is not listed in packages/CHECKSUMS.sha256. "
                "Add its SHA-256 before installing.",
                file=sys.stderr,
            )
            sys.exit(1)
        actual = hashlib.sha256(whl.read_bytes()).hexdigest()
        if actual != expected[whl.name]:
            print(
                f"ERROR: integrity check failed for {whl.name}.\n"
                f"  expected: {expected[whl.name]}\n"
                f"  got:      {actual}",
                file=sys.stderr,
            )
            sys.exit(1)


packages_dir = Path("packages")
if packages_dir.exists():
    _verify_package_checksums(packages_dir)

dependency_links = []
install_requires = []

if packages_dir.exists():
    for whl in packages_dir.glob("*.whl"):
        name = whl.stem.split("-")[0]
        dependency_links.append(f"file:{whl}")
        install_requires.append(name)

setup(
    name="fractum",
    version=VERSION,
    packages=find_packages(),
    install_requires=install_requires,
    dependency_links=dependency_links,
    setup_requires=["wheel"],
    entry_points={
        "console_scripts": [
            "fractum=src.__init__:cli",
        ],
    },
    python_requires=(
        f"=={REQUIRED_PYTHON_VERSION[0]}"
        f".{REQUIRED_PYTHON_VERSION[1]}"
        f".{REQUIRED_PYTHON_VERSION[2]}"
    ),
)
