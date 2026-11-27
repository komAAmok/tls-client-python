#!/usr/bin/env python3
"""One measurement child for interleaved_ab.py: N round trips, print latencies.

Runs in its own interpreter and owns its own origin server, so no state leaks
between samples.  Arguments: tree-root, body-size, count, server-binary.

The import is asserted to come from *tree-root*: a silently wrong sys.path
would compare one tree against itself and report a perfect 0% change.
"""
import subprocess
import sys
import time

root, size, count, server = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
sys.path.insert(0, root)

import tls_client  # noqa: E402

if not tls_client.__file__.startswith(root):
    raise SystemExit("imported %s, expected a path under %s" % (tls_client.__file__, root))

proc = subprocess.Popen(
    [server, "-addr", "127.0.0.1:0", "-print-port"],
    stdout=subprocess.PIPE, text=True,
)
addr = proc.stdout.readline().strip()
try:
    from tls_client import Session

    session = Session(timeout=300)
    url = "http://%s/x?len=%d" % (addr, size)
    for _ in range(20):
        session.get(url)
    out = []
    for _ in range(count):
        started = time.perf_counter()
        resp = session.get(url)
        out.append((time.perf_counter() - started) * 1000)
        if len(resp.content) != size:
            raise SystemExit("short body: %d != %d" % (len(resp.content), size))
    session.close()
finally:
    proc.terminate()
print(",".join("%.3f" % v for v in out))
