#!/usr/bin/env python3
"""
Test different TLS client_identifier values against httpbin.org (Cloudflare).

Runs a quick GET to /ip for each profile, reports status_code + protocol.
"""
import sys, time

# Profiles to test — diverse set covering Chrome/Firefox/Safari/Brave/Opera/OkHttp
CANDIDATES = [
    # Chrome (various versions)
    "chrome_146", "chrome_144", "chrome_133", "chrome_131",
    "chrome_124", "chrome_120", "chrome_117",
    # Chrome PSK variants
    "chrome_146_PSK", "chrome_144_PSK", "chrome_133_PSK", "chrome_131_PSK",
    # Firefox
    "firefox_148", "firefox_147", "firefox_133", "firefox_132",
    # Safari (iOS)
    "safari_ios_18_5", "safari_ios_18_0", "safari_16_0",
    # Brave
    "brave_146", "brave_146_PSK",
    # Opera
    "opera_91",
    # OkHttp (Android) — often bypasses Cloudflare
    "okhttp4_android_13",
    # Built for Cloudflare
    "cloudscraper",
]

URL = "https://jzsc.mohurd.gov.cn/home"
PASS = 0
FAIL = 0

print(f"{'PROFILE':<28} {'STATUS':>7} {'PROTO':>10}  NOTE")
print("-" * 70)

from tls_client import Session

for profile in CANDIDATES:
    try:
        s = Session(client_identifier=profile, timeout=15, catch_panics=True)
        resp = s.get(URL)
        status = resp.status_code
        proto = resp.used_protocol or "?"
        tag = "✅" if resp.ok else "❌"
        if resp.ok:
            PASS += 1
            # Show a bit of response for confidence
            snippet = resp.text[:60].replace("\n", " ").strip()
            note = f"body: {snippet}"
        else:
            FAIL += 1
            snippet = (resp.text or resp.content[:60] or b"").decode("utf-8", errors="replace")[:40].strip()
            note = f"body: {snippet}" if snippet else "empty body"
        print(f"{profile:<28} {status:>7} {proto:>10}  {tag} {note}")
    except RuntimeError as e:
        FAIL += 1
        err = str(e)[:60]
        print(f"{profile:<28} {'ERROR':>7} {'':>10}  ❌ {err}")
    except Exception as e:
        FAIL += 1
        print(f"{profile:<28} {'CRASH':>7} {'':>10}  ❌ {type(e).__name__}: {e}")
    time.sleep(0.3)  # polite rate limiting

print("-" * 70)
print(f"RESULTS:  {PASS} bypassed  /  {FAIL} blocked")
if PASS > 0:
    sys.exit(0)
else:
    print("\n⚠️  All profiles blocked.  httpbin.org may be fully rate-limiting this IP.")
    sys.exit(1)
