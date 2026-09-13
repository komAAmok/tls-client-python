"""Verify tls_client/bin/ covers every platform the package advertises.

``tls_client/_core.py`` resolves a core library at import time by building a
filename from ``(sys.platform, platform.machine(), libc)``.  If that computed
name is not present in ``tls_client/bin/``, import fails for that platform --
no fallback, no clear message, just ``FileNotFoundError``.

Historically the committed set covered four of the twelve advertised targets,
so ``linux_x86_64`` (the most common target of all) shipped a wheel that could
not open its own core.  This gate makes a missing target a build failure.

The twelve targets are the contract; keep them in sync with the header comment
in ``.github/workflows/build_workflow.yml``.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BIN_DIR = REPO_ROOT / "tls_client" / "bin"

# (human label, expected filename in tls_client/bin/)
TARGETS: list[tuple[str, str]] = [
    ("win x86_64", "tls-client-windows-amd64.dll"),
    ("win x86", "tls-client-windows-386.dll"),
    ("win arm64", "tls-client-windows-arm64.dll"),
    ("linux x86_64", "tls-client-linux-amd64.so"),
    ("linux arm64", "tls-client-linux-arm64.so"),
    ("linux armv7", "tls-client-linux-arm.so"),
    ("linux i386", "tls-client-linux-386.so"),
    ("macos x86_64", "tls-client-darwin-amd64.dylib"),
    ("macos arm64", "tls-client-darwin-arm64.dylib"),
    ("linux-x86_64-musl", "tls-client-linux-amd64-musl.so"),
    ("linux-aarch64-musl", "tls-client-linux-arm64-musl.so"),
    ("linux-armv7-musl", "tls-client-linux-arm-musl.so"),
]


def _expected_full_names() -> dict[str, str]:
    """filename -> human label, for the canonical (full) tier."""
    return {filename: label for label, filename in TARGETS}


def main() -> int:
    if not BIN_DIR.is_dir():
        print(f"FAIL: {BIN_DIR} does not exist", file=sys.stderr)
        return 1

    present = {
        p.name for p in BIN_DIR.iterdir() if p.is_file() and p.name.startswith("tls-client-")
    }
    expected = _expected_full_names()

    missing = sorted(name for name in expected if name not in present)
    extra = sorted(name for name in present if name not in expected)

    print(f"core libraries committed: {len(present)}")
    for label, filename in TARGETS:
        mark = "ok  " if filename in present else "MISS"
        print(f"  [{mark}] {label:20s} {filename}")

    if missing:
        print(
            "\nFAIL: the package advertises these platforms but ships no core "
            "library for them, so `import tls_client` raises FileNotFoundError:\n"
            + "\n".join(
                f"  {expected[name]:20s} {name}" for name in missing
            ),
            file=sys.stderr,
        )
        return 1

    if extra:
        # Not fatal: a stale artifact from a removed target is only wasted
        # space, but it is worth surfacing.
        print(
            "\nWARNING: unexpected core libraries present (not in the matrix):\n"
            + "\n".join(f"  {name}" for name in extra),
            file=sys.stderr,
        )

    print(f"\nOK: all {len(TARGETS)} advertised targets have a core library.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
