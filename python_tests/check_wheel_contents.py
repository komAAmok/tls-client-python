"""Assert a built wheel carries exactly the expected payload.

Two payload classes must be checked, because both fail the same way at the
user's end — ``pip install`` succeeds and the first ``import tls_client``
raises:

1. **The native core library.**  A wheel that ships the wrong core, or more
   than one, is worse than a failed build: the import either raises
   ``FileNotFoundError`` (nothing to dlopen) or loads a foreign architecture
   and raises ``OSError``.  Twelve platforms are published, so "just ship
   everything" would put eleven foreign cores in every wheel.

2. **The Python source tree.**  Every ``.py`` module and subpackage under
   ``tls_client/`` (plus the PEP 561 ``py.typed`` marker) must be present.
   Historically ``tls_client.fingerprints`` was added to the source tree but
   left out of ``[tool.setuptools] packages``, so it was silently absent from
   wheels and ``import tls_client`` raised ``ImportError: cannot import name
   'fingerprints'`` — while every source-level test still passed.  Deriving
   the required file list from the source tree makes a new module or
   subpackage automatically required, so this class of bug cannot recur.

Usage:
    python check_wheel_contents.py --dir dist --expect tls-client-linux-amd64.so

Exits non-zero with a readable diff when the payload does not match.
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path

BIN_PREFIX = "tls_client/bin/"

# The Python layer ships as source modules/subpackages, not just binaries.
SRC_DIR = Path(__file__).resolve().parent.parent / "tls_client"


def _payload(zf: zipfile.ZipFile) -> list[str]:
    return sorted(
        n
        for n in zf.namelist()
        if n.startswith(BIN_PREFIX) and not n.endswith("/")
    )


def _required_python_files() -> list[str]:
    """Every source ``.py`` plus the PEP 561 marker that must ship in a wheel."""
    files = [
        "tls_client/" + str(p.relative_to(SRC_DIR)).replace("\\", "/")
        for p in SRC_DIR.rglob("*.py")
    ]
    files.append("tls_client/py.typed")
    return sorted(set(files))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dir", default="dist", help="directory holding the wheel")
    ap.add_argument(
        "--expect",
        required=True,
        action="append",
        help="library filename the wheel must contain, e.g. "
        "tls-client-linux-amd64.so.  Repeat for wheels that legitimately "
        "bundle more than one architecture (macOS universal2).",
    )
    args = ap.parse_args()

    wheels = sorted(Path(args.dir).glob("*.whl"))
    if not wheels:
        print(f"FAIL: no wheel found in {args.dir!r}", file=sys.stderr)
        return 1
    if len(wheels) > 1:
        print(
            f"FAIL: expected exactly one wheel in {args.dir!r}, found "
            f"{[w.name for w in wheels]}",
            file=sys.stderr,
        )
        return 1

    wheel = wheels[0]
    with zipfile.ZipFile(wheel) as zf:
        found = _payload(zf)
        wheel_names = set(zf.namelist())

    expected = sorted(f"{BIN_PREFIX}{name}" for name in args.expect)
    print(f"wheel:    {wheel.name}")
    for name in expected:
        print(f"expected: {name}")
    for name in found:
        print(f"found:    {name}")

    if found != expected:
        print(
            "\nFAIL: wheel payload does not match this target.\n"
            f"  wanted exactly: {expected}\n"
            f"  got:            {found}",
            file=sys.stderr,
        )
        return 1

    # Python package files: a dropped subpackage would otherwise pass the
    # binary check above while breaking ``import tls_client`` on install.
    missing_py = [n for n in _required_python_files() if n not in wheel_names]
    if missing_py:
        print(
            "\nFAIL: wheel is missing Python package files:\n"
            + "\n".join(f"  {n}" for n in missing_py),
            file=sys.stderr,
        )
        return 1

    print(
        f"\nOK: exactly {len(expected)} core librar{'y' if len(expected) == 1 else 'ies'}, "
        "and every Python source file is present."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
