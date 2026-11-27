#!/usr/bin/env python3
"""Alternating A/B benchmark runner.

A single before/after pair is worthless on a shared machine: this host runs a
browser that holds one core, so two runs minutes apart differ by more than the
optimisation does.  Alternating the two trees round by round and taking the
median of the per-round ratios cancels the drift instead of averaging it in.

    python benchmarks/ab.py --scenario sync-sequential --rounds 3 \
        --a <git-rev-or-.> --b <git-rev-or-.>

Both trees must already be checked out somewhere with the shared library
built; the script never rebuilds.  It runs the harness in each tree and
compares the JSON it writes.
"""
import argparse
import json
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path


def run_tree(root, scenario, out_path):
    harness = Path(root) / "benchmarks" / "harness.py"
    cmd = [
        sys.executable, str(harness),
        "--scenario", scenario,
        "--json", str(out_path),
    ]
    proc = subprocess.run(
        cmd, cwd=str(root), capture_output=True, text=True, timeout=3600,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "harness failed in %s\n%s\n%s" % (root, proc.stdout[-2000:], proc.stderr[-2000:])
        )
    return json.loads(out_path.read_text())["results"][scenario]


def flatten(prefix, value, out):
    """Turn nested scenario results into leaf scalars."""
    if isinstance(value, dict):
        for key, sub in value.items():
            if key.startswith("_"):
                continue
            flatten("%s.%s" % (prefix, key) if prefix else key, sub, out)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        out[prefix] = float(value)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--a", required=True, help="baseline tree root")
    ap.add_argument("--b", required=True, help="candidate tree root")
    ap.add_argument("--json", default="")
    args = ap.parse_args()

    ratios = {}
    raw = {"a": [], "b": []}
    with tempfile.TemporaryDirectory() as tmp:
        for i in range(args.rounds):
            for tag, root in (("a", args.a), ("b", args.b)):
                out = Path(tmp) / ("%s-%d.json" % (tag, i))
                flat = flatten("", run_tree(root, args.scenario, out), {})
                raw[tag].append(flat)
            print("round %d/%d done" % (i + 1, args.rounds), file=sys.stderr, flush=True)

    keys = set(raw["a"][0]) & set(raw["b"][0])
    for key in sorted(keys):
        a_vals = [r[key] for r in raw["a"] if key in r]
        b_vals = [r[key] for r in raw["b"] if key in r]
        if not a_vals or not b_vals:
            continue
        a_med = statistics.median(a_vals)
        b_med = statistics.median(b_vals)
        ratios[key] = {
            "a_median": round(a_med, 3),
            "b_median": round(b_med, 3),
            "change_pct": round((b_med / a_med - 1) * 100, 1) if a_med else None,
            "a_all": [round(v, 3) for v in a_vals],
            "b_all": [round(v, 3) for v in b_vals],
        }
    payload = {"scenario": args.scenario, "rounds": args.rounds, "metrics": ratios}
    text = json.dumps(payload, indent=2, sort_keys=True)
    if args.json:
        Path(args.json).write_text(text)
    print(text)


if __name__ == "__main__":
    main()
