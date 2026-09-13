"""Pin the naming contract between the wheel payload and the import loader.

``tls_client/_core.py`` computes the core library filename from the *running*
interpreter's ``sys.platform``, ``platform.machine()`` and libc, and dlopens
exactly ``tls_client/bin/<that name>``.  The CI build jobs write files whose
names are assembled independently, in YAML.  Nothing historically tied the two
together, so a divergence would ship a wheel whose payload exists but can
never be loaded.

This test executes the loader's own pure functions against every advertised
platform's ``(sys.platform, machine, libc)`` triple and asserts the result is
exactly the filename the build matrix produces.  It needs no compiled library
and no compiled artifact, so it is safe to run before any build.

Keep TARGETS in sync with ``python_tests/check_platform_matrix.py`` and the
matrix header in ``.github/workflows/build_workflow.yml``.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# (label, sys.platform, platform.machine(), libc, expected filename)
TARGETS: list[tuple[str, str, str, str, str]] = [
    ("win x86_64", "win32", "AMD64", "glibc", "tls-client-windows-amd64.dll"),
    ("win x86", "win32", "x86", "glibc", "tls-client-windows-386.dll"),
    ("win arm64", "win32", "ARM64", "glibc", "tls-client-windows-arm64.dll"),
    ("linux x86_64", "linux", "x86_64", "glibc", "tls-client-linux-amd64.so"),
    ("linux arm64", "linux", "aarch64", "glibc", "tls-client-linux-arm64.so"),
    ("linux armv7", "linux", "armv7l", "glibc", "tls-client-linux-arm.so"),
    ("linux i386", "linux", "i686", "glibc", "tls-client-linux-386.so"),
    ("macos x86_64", "darwin", "x86_64", "glibc", "tls-client-darwin-amd64.dylib"),
    ("macos arm64", "darwin", "arm64", "glibc", "tls-client-darwin-arm64.dylib"),
    ("linux x86_64 musl", "linux", "x86_64", "musl", "tls-client-linux-amd64-musl.so"),
    ("linux arm64 musl", "linux", "aarch64", "musl", "tls-client-linux-arm64-musl.so"),
    ("linux armv7 musl", "linux", "armv7l", "musl", "tls-client-linux-arm-musl.so"),
]


class _Patched:
    """Temporarily rebind sys.platform / platform.machine / _detect_libc."""

    def __init__(self, plat: str, machine: str, libc: str):
        self.plat, self.machine, self.libc = plat, machine, libc

    def __enter__(self):
        import platform as _platform

        import tls_client._core as core

        self._core = core
        self._orig = (sys.platform, core.platform.machine, core._detect_libc)
        # _shared_lib_name() reads sys.platform and platform.machine directly,
        # and _libc_suffix() calls _detect_libc(), so patch all three.
        sys.platform = self.plat
        core.platform.machine = lambda: self.machine
        core._detect_libc = lambda: self.libc
        return core

    def __exit__(self, *exc):
        sys.platform, machine, libc = self._orig
        self._core.platform.machine = machine
        self._core._detect_libc = libc
        return False


class TestCoreNamingContract(unittest.TestCase):
    def test_loader_name_matches_build_matrix(self) -> None:
        for label, plat, machine, libc, expected in TARGETS:
            with self.subTest(target=label):
                with _Patched(plat, machine, libc) as core:
                    actual = core._shared_lib_name()
                self.assertEqual(
                    actual,
                    expected,
                    f"{label}: loader would dlopen {actual!r} but the build "
                    f"matrix produces {expected!r}",
                )

    def test_every_target_name_is_unique(self) -> None:
        names = [t[4] for t in TARGETS]
        self.assertEqual(
            len(names), len(set(names)), f"duplicate library names: {names}"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
