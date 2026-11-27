#!/usr/bin/env python3
"""Sample-interleaved A/B benchmark.

`ab.py` alternates whole *runs*: it spawns a fresh interpreter per tree, so the
two measurements are tens of seconds apart.  On a host whose load average
swings between 2.5 and 9.9 that is not tight enough - per-round samples for
one tree spanned 4.6 ms to 16.7 ms for the same 1 MiB request, which made the
result both unstable and biased low.

This script interleaves at the sample level instead: for one body size it runs
tree A, then tree B, then A, then B, swapping the order every round, and takes
the median over all samples.  Both trees see the same load by construction.

    python benchmarks/interleaved_ab.py \
        --a /path/to/baseline-tree --b /path/to/candidate-tree \
        --sizes 262144 1048576 10485760 --rounds 5 --per-round 8

Both trees must be complete working trees with a shared library in
`tls_client/bin/`.  **They must use the same shared library build**, otherwise
the comparison measures the binary rather than the code.
"""
import argparse
import json
import os
import statistics
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHILD = HERE / "_ab_child.py"


def run_tree(python, root, size, n, server):
    proc = subprocess.run(
        [python, str(CHILD), root, str(size), str(n), server],
        capture_output=True, text=True, timeout=1800,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "child failed for %s\n%s" % (root, proc.stderr[-1500:])
        )
    return [float(x) for x in proc.stdout.strip().split(",") if x]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--a", required=True, help="baseline tree root")
    ap.add_argument("--b", required=True, help="candidate tree root")
    ap.add_argument("--sizes", type=int, nargs="+", default=[262144, 1048576, 10485760])
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--per-round", type=int, default=8)
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--server", default="/tmp/benchserver")
    ap.add_argument("--json", default="")
    args = ap.parse_args()

    if not Path(args.server).exists():
        raise SystemExit(
            "benchmark server missing: %s\n  go build -o %s ./benchmarks/server"
            % (args.server, args.server)
        )

    report = {"a": args.a, "b": args.b, "rounds": args.rounds,
              "per_round": args.per_round, "results": {}}
    for size in args.sizes:
        a_all, b_all = [], []
        for rd in range(args.rounds):
            # swap the order each round so neither tree always runs first
            if rd % 2 == 0:
                a_all += run_tree(args.python, args.a, size, args.per_round, args.server)
                b_all += run_tree(args.python, args.b, size, args.per_round, args.server)
            else:
                b_all += run_tree(args.python, args.b, size, args.per_round, args.server)
                a_all += run_tree(args.python, args.a, size, args.per_round, args.server)
        a_med = statistics.median(a_all)
        b_med = statistics.median(b_all)
        entry = {
            "a_median_ms": round(a_med, 3),
            "b_median_ms": round(b_med, 3),
            "change_pct": round((b_med / a_med - 1) * 100, 1) if a_med else None,
            "a_min": round(min(a_all), 3),
            "b_min": round(min(b_all), 3),
            "a_p95": round(sorted(a_all)[int(len(a_all) * 0.95)], 3),
            "b_p95": round(sorted(b_all)[int(len(b_all) * 0.95)], 3),
            "samples": len(a_all),
            "load": round(os.getloadavg()[0], 2),
        }
        report["results"][str(size)] = entry
        print("size=%-9d before=%8.3f after=%8.3f %+7.1f%%  min %7.3f->%7.3f  load=%.1f"
              % (size, entry["a_median_ms"], entry["b_median_ms"], entry["change_pct"],
                 entry["a_min"], entry["b_min"], entry["load"]), flush=True)

    text = json.dumps(report, indent=2, sort_keys=True)
    if args.json:
        Path(args.json).write_text(text)
        print("wrote %s" % args.json, file=sys.stderr)
    print(text)


if __name__ == "__main__":
    main()
