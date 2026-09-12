#!/usr/bin/env python3
"""Extract Chrome 99-153 TLS/HTTP-2 fingerprint captures into a compact JSON.

Reads the ``tls-results*.json`` files produced by tls-chrome (one entry per
Chrome major version, each holding a tls.peet.ws ``/api/all`` response) and
normalises them into the shape consumed by ``gen_chrome_profiles.py``.

Run from the repository root:

    python tools/extract_chrome_captures.py --src ../tls-chrome \
        --out tools/_chrome_captures.json

The output is an intermediate artefact only; the committed source of truth is
the generated Go file under ``profiles/``.
"""

import argparse
import glob
import json
import os
import re
import sys

# Wire-format extension name -> numeric id.  tls.peet.ws labels most
# extensions by name, so we map them back and only fall back to the trailing
# "(NNN)" when a name is unknown.
_EXT_NAME_IDS = {
    "server_name": 0,
    "extended_master_secret": 23,
    "extensionRenegotiationInfo": 65281,
    "supported_groups": 10,
    "ec_point_formats": 11,
    "session_ticket": 35,
    "application_layer_protocol_negotiation": 16,
    "status_request": 5,
    "signature_algorithms": 13,
    "signed_certificate_timestamp": 18,
    "key_share": 51,
    "psk_key_exchange_modes": 45,
    "supported_versions": 43,
    "compress_certificate": 27,
    "application_settings_old": 17513,
    "application_settings": 17613,
    "extensionEncryptedClientHello": 65037,
    "extensionEncryptedClientHelloOuter": 64768,
    "record_size_limit": 28,
    "padding": 21,
    "delegated_credentials": 34,
    "post_handshake_auth": 49,
    "certificate_authorities": 47,
    "SignedCertificateTimestamp": 18,
}


def _ext_id(entry):
    """Return the numeric id for one entry of tls.extensions, or None."""
    name = entry.get("name", "")
    if name.startswith("TLS_GREASE"):
        return "G"

    # "Unknown extension 51764" carries the id without parentheses.
    m = re.search(r"[Uu]nknown extension (\d+)", name)
    if m:
        return int(m.group(1))

    m = re.search(r"\((\d+)\)", name)
    if not m:
        return None

    num = int(m.group(1))
    # Prefer the name map when it agrees with the trailing number.
    for key, val in _EXT_NAME_IDS.items():
        if key.lower() in name.lower() and val == num:
            return val
    return num


def _sig_algs(entry_list):
    for entry in entry_list:
        if entry.get("name", "").startswith("signature_algorithms"):
            return entry.get("signature_algorithms")
    return None


def load_best(src):
    """Merge every capture file, preferring a successful record per version."""
    best = {}
    for path in sorted(glob.glob(os.path.join(src, "tls-results*.json"))):
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        for raw_key, entry in data.items():
            if "data" not in entry:
                continue
            try:
                major = int(raw_key)
            except ValueError:
                continue

            prev = best.get(major)
            has_h2 = bool((entry["data"].get("http2") or {}).get("akamai_fingerprint"))
            prev_h2 = bool((prev["data"].get("http2") or {}).get("akamai_fingerprint")) if prev else False
            if prev is None or (has_h2 and not prev_h2):
                best[major] = entry
    return best


def normalise(entry):
    data = entry["data"]
    tls = data["tls"]
    ja3 = tls["ja3"]
    _, cipher_part, ext_part, curve_part, _ = ja3.split(",")

    extensions = []
    for ext in tls["extensions"]:
        extensions.append(_ext_id(ext))

    http2 = data.get("http2") or {}
    return {
        "version": entry["version"],
        "user_agent": data.get("user_agent"),
        "cipher_hex": [int(c) for c in cipher_part.split("-")],
        "ext_hex": ext_part,
        "ext_ids": extensions,
        "curve_hex": [int(c) for c in curve_part.split("-")],
        "ja3": ja3,
        "ja3_hash": tls.get("ja3_hash"),
        "ja4": tls.get("ja4"),
        "akamai": http2.get("akamai_fingerprint"),
        "akamai_hash": http2.get("akamai_fingerprint_hash"),
        "signature_algorithms": _sig_algs(tls["extensions"]),
        "http_version": data.get("http_version"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=os.path.join("..", "tls-chrome"))
    ap.add_argument("--out", default=os.path.join("tools", "_chrome_captures.json"))
    args = ap.parse_args()

    best = load_best(args.src)
    out = {str(k): normalise(v) for k, v in sorted(best.items())}

    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(out, handle, indent=1, sort_keys=True)

    majors = sorted(int(k) for k in out)
    print("wrote %s: %d versions (%d..%d)" % (args.out, len(out), majors[0], majors[-1]))
    missing = [k for k in range(majors[0], majors[-1] + 1) if k not in majors]
    if missing:
        print("missing majors: %s" % missing, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
