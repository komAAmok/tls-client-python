"""Assert a built wheel carries exactly the expected shared library.

A wheel that ships the wrong core library, or more than one, is worse than a
failed build: ``pip install`` succeeds and the first ``import tls_client``
either raises ``FileNotFoundError`` (nothing to dlopen) or loads a foreign
architecture and raises ``OSError``.  Twelve platforms are published, so
"just ship everything" would put eleven foreign cores in every wheel.

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


def _payload(zf: zipfile.ZipFile) -> list[str]:
    return sorted(
        n
        for n in zf.namelist()
        if n.startswith(BIN_PREFIX) and not n.endswith("/")
    )


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

    print(f"\nOK: exactly {len(expected)} core librar{'y' if len(expected) == 1 else 'ies'}, and it matches the expected set.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
