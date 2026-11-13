# -*- coding: utf-8 -*-
"""Start the repository's WebSocket echo fixture for a test module.

The fixture is a Go program (python_tests/fixtures/ws_echo_server.go) because
the project has no Python WebSocket server dependency.  It is compiled once into
the test cache on first use, so a checkout with a Go toolchain needs no setup and
a checkout without one skips the tests instead of failing them.
"""

import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "python_tests" / "fixtures" / "ws_echo_server.go"


def _binary() -> Path:
    return ROOT / ".cache" / "ws_echo_server"


def _go_binary():
    """Locate the Go toolchain: PATH first, then the project-local install."""
    found = shutil.which("go")
    if found:
        return found
    for candidate in (
        ROOT / ".cache" / "goroot" / "go" / "bin" / "go",
        Path.home() / ".local" / "goroot" / "go" / "bin" / "go",
        Path("/usr/local/go/bin/go"),
    ):
        if candidate.exists():
            return str(candidate)
    return None


def _build() -> Path:
    binary = _binary()
    if binary.exists() and binary.stat().st_mtime >= FIXTURE.stat().st_mtime:
        return binary
    go = _go_binary()
    if go is None:
        raise RuntimeError("no Go toolchain to build the websocket fixture")
    binary.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.setdefault("GOFLAGS", "-mod=mod")
    # A project-local toolchain needs its GOROOT to find the standard library,
    # and Go refuses to build at all without a build cache.
    goroot = Path(go).resolve().parent.parent
    if (goroot / "src").is_dir():
        env.setdefault("GOROOT", str(goroot))
    env.setdefault("GOCACHE", str(ROOT / ".cache" / "go-build"))
    env.setdefault("GOMODCACHE", str(ROOT / ".cache" / "go-mod"))
    env.setdefault("GOTMPDIR", str(ROOT / ".cache" / "go-tmp"))
    for key in ("GOCACHE", "GOMODCACHE", "GOTMPDIR"):
        Path(env[key]).mkdir(parents=True, exist_ok=True)
    subprocess.run([go, "build", "-o", str(binary), str(FIXTURE)],
                   cwd=str(ROOT), env=env, check=True)
    return binary


def start(port: int = 18841) -> subprocess.Popen:
    """Start the echo server and wait until it accepts connections."""
    binary = _build()
    proc = subprocess.Popen([str(binary), "-addr", "127.0.0.1:%d" % port],
                            stderr=subprocess.DEVNULL)
    deadline = time.time() + 10.0
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("websocket fixture exited early")
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return proc
        except OSError:
            time.sleep(0.05)
    proc.terminate()
    raise RuntimeError("websocket fixture did not start")


def stop(proc: subprocess.Popen) -> None:
    if proc is None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
