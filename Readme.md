# tls-client-python

> **维护边界：** Go 引擎同步自上游，本项目的 Python/CFFI 扩展及冲突保留规则见
> [`UPSTREAM_SYNC.md`](UPSTREAM_SYNC.md)。日常修改请勿直接改动上游归属区域。

[![PyPI version](https://img.shields.io/pypi/v/tls-client-python)](https://pypi.org/project/tls-client-python/)
[![Python](https://img.shields.io/pypi/pyversions/tls-client-python)](https://pypi.org/project/tls-client-python/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**CFFI-based, high-performance Python binding for [`tls-client`](https://github.com/bogdanfinn/tls-client) — drop-in compatible with [`requests`](https://github.com/psf/requests) and [`Python-Tls-Client`](https://github.com/FlorianREGAZ/Python-Tls-Client).**
---

## What is TLS Fingerprinting?

Some people think it is enough to change the user-agent header of a request to let the server think that the client
requesting a resource is a specific browser.
Nowadays this is not enough, because the server might use a technique to detect the client browser which is called TLS
Fingerprinting.

For a deep dive, see [this excellent article on TLS fingerprinting](https://httptoolkit.tech/blog/tls-fingerprinting-node-js/#how-does-tls-fingerprinting-work).

## ✨ Features

| Category | Details |
|----------|---------|
| 🔐 **TLS Fingerprinting** | Impersonate Chrome, Firefox, Safari, Brave, Opera, OkHttp & more |
| 🌐 **Protocol Support** | HTTP/1.1, HTTP/2 (h2), HTTP/3 (QUIC) with automatic negotiation |
| ⚡ **Protocol Racing** | Chrome-style Happy Eyeballs for HTTP/2 vs HTTP/3 |
| 📋 **Header Ordering** | Control the exact order of HTTP headers per request |
| 🔒 **Certificate Pinning** | Pin server certificates for enhanced security |
| 🍪 **Cookie Jar** | Built-in cookie handling with customisable jar |
| 🚇 **Proxy Support** | HTTP and SOCKS5 proxies with CONNECT auth |
| 🔀 **Redirect Control** | Choose whether to follow redirects per request |
| 📊 **Bandwidth Tracking** | Monitor upload/download bytes in real time |
| 🔄 **sync/Async** | `Session`  +  `AsyncSession` |
| 🔌 **WebSocket** | TLS-fingerprinted WebSocket (HTTP/1.1 handshake) — `WebSocket` |
| 🛡️ **Panic-proof** | All Go panics caught and surfaced as Python exceptions |
| ⚙️ **Custom TLS** | Full 26-field custom TLS client configuration |
| 🔬 **Chrome 99–153 Captures** | Byte-exact profiles for **every** Chrome major 99…153, recovered from live handshakes |
| 🎲 **Per-Handshake Extension Shuffle** | Chromium's unseeded extension rotation, with GREASE/padding/PSK pinned (`ABI 3`) |
| 🧭 **Destination-Aware Header Order** | Header order selected by `Sec-Fetch-Dest` — navigation vs sub-resource (`ABI 3`) |
| 🌐 **Deep TCP Fingerprint** | DF bit, TOS, Nagle, window clamp and IP-ID mode (`ABI 3`) |
| 🎯 **Fingerprint Presets** | Coherent per-OS bundles: identifier + headers + header order + TCP fingerprint (`tls_client.fingerprints`) |
| 🧭 **Request Contexts** | Browser-coherent `Sec-Fetch-*`, Client Hints and RFC 9218 `Priority` headers (`RequestContext`) |
| 🔏 **Trust Anchors / ECH** | Chrome 152 `0xCA34` trust anchors and automatic ECH config resolution over DoH |
| 🪶 **Full-fidelity build** | A single full build (QUIC/HTTP-3 + the complete profile catalogue) |

> **macOS TCP fingerprinting:** macOS derives TCP MSS during `connect` and
> rejects `TCP_MAXSEG` in the pre-connect socket hook. The MSS hint is therefore
> skipped on macOS; TTL, receive-window tuning, and TLS/HTTP fingerprints remain
> active. This avoids `MSS(1460): invalid argument` on macOS 26 and earlier.

---

## 📦 Installation

```bash
pip install tls-client-python
```

Pre-compiled binaries are included for **12 platforms** (plus a macOS universal2 wheel) — no Go toolchain required.

> **Requirements:** Python 3.6+

---

## 🚀 Quick Start

```python
from tls_client import Session

# Create a session with Chrome 146 fingerprint
session = Session(client_identifier="chrome_146", verify=False)

# GET request
resp = session.get("https://tls.browserleaks.com/json")
print(resp.status_code)
print(resp.text)

# POST request
resp = session.post("https://tools.scrapfly.io/api/fp/ja3")
data = resp.json()
print(resp.status_code)
print(data)


# Context Manager
with Session(client_identifier="firefox_148") as session:
    resp = session.get("https://tls.browserleaks.com/json")
    print(resp.status_code)
    print(resp.text)


# Async Usage
import asyncio
from tls_client import AsyncSession

async def main():
    async with AsyncSession(client_identifier="firefox_148") as s:
        resp = await s.get("https://tls.browserleaks.com/json")
        print(resp.status_code)
        print(resp.json())

asyncio.run(main())
```

### Requests-compatible API

The synchronous API implements Requests-style request preparation, session
state, redirects, cookies, hooks, exceptions, and response objects without
depending on the Requests package. Network transport remains the native
tls-client engine:

```python
import tls_client

response = tls_client.get(
    "https://example.com/api",
    params={"page": 1},
    headers={"Accept": "application/json"},
    timeout=(3.05, 30),
)
response.raise_for_status()
print(response.json())

with tls_client.Session(client_identifier="chrome_146") as session:
    session.headers.update({"Authorization": "Bearer token"})
    response = session.post(
        "https://example.com/upload",
        files={"file": ("data.txt", b"payload")},
        hooks={"response": lambda r, *args, **kwargs: r},
    )
```

`Request`, `PreparedRequest`, `Response`, `exceptions`, `codes`, `cookies`,
`auth`, `adapters`, `structures`, and all top-level HTTP helpers follow the
commonly used Requests API. The previous low-level objects remain available as `NativeSession`,
`NativeResponse`, and `TLSRequest`. `stream=True` exposes the normal Requests
iteration API, but the current native ABI buffers the response before Python
receives it. A string `verify` value enables verification with system roots;
passing a custom CA bundle through the C ABI is not yet supported.

---

## 🖥️ Supported Platforms

Pre-compiled native libraries are bundled for these platforms:

| OS | Architecture | Binary |
|----|-------------|--------|
| **Windows** | x86-64 | `tls-client-windows-amd64.dll` |
| **Windows** | x86 (32-bit) | `tls-client-windows-386.dll` |
| **Windows** | ARM64 | `tls-client-windows-arm64.dll` |
| **macOS** | x86-64 | `tls-client-darwin-amd64.dylib` |
| **macOS** | ARM64 (Apple Silicon) | `tls-client-darwin-arm64.dylib` |
| **macOS** | Universal (both) | one `universal2` wheel, both binaries |
| **Linux** | x86-64 (glibc) | `tls-client-linux-amd64.so` |
| **Linux** | x86 (32-bit, glibc) | `tls-client-linux-386.so` |
| **Linux** | ARM64 | `tls-client-linux-arm64.so` |
| **Linux** | ARMv7 | `tls-client-linux-arm.so` |
| **Linux** | x86-64 (musl) | `tls-client-linux-amd64-musl.so` |
| **Linux** | ARM64 (musl) | `tls-client-linux-arm64-musl.so` |
| **Linux** | ARMv7 (musl) | `tls-client-linux-arm-musl.so` |

The correct binary is automatically selected at runtime. Override via `TLS_CLIENT_LIB` environment variable.

---

## 🎭 Supported Browser Profiles

The complete, runtime-validated list is exported as
`tls_client.SUPPORTED_CLIENT_IDENTIFIERS`. It is also used for IDE/type
checking through `ClientIdentifiers`.

### 🌐 Chrome — 79 Profiles (captured 99–153 + hand-written)

The full Chrome range **99 through 153** is available, recovered from live
handshakes rather than hand-transcribed. Every major ships as both
`chrome_<major>` and `chrome_<major>_PSK`:

| Identifier | Notes |
|-----------|-------|
| `chrome_99` — `chrome_153` | **Byte-exact captures, every major 99…153** |
| `chrome_99_PSK` — `chrome_153_PSK` | Same, with PSK key exchange |

The captures pin the real per-version cipher list, extension order, supported
groups, signature algorithms, JA3/JA4 and HTTP/2 Akamai fingerprint — so
`chrome_111`, `chrome_121`, `chrome_137` etc. reproduce the wire bytes of that
exact release, including the per-milestone extension-order reshuffles.

Hand-written profiles with PSK / Post-Quantum / trust-anchor refinements
(`chrome_116_PSK_PQ`, `chrome_130_PSK`, `chrome_144`, `chrome_146`,
`chrome_150`, `chrome_152`, …) remain authoritative where they exist.

| Identifier | Notes |
|-----------|-------|
| `chrome_116_PSK_PQ` | Chrome 116 with PSK + Post-Quantum |
| `chrome_130_PSK` · `chrome_131_PSK` · `chrome_133_PSK` | PSK variants |
| `chrome_144` · `chrome_146` · `chrome_150` · `chrome_152` | standard + PSK |
| `chrome_146` | **default identifier** (standard & PSK) |

### 🦊 Firefox — 16 Profiles

| Identifier | Notes |
|-----------|-------|
| `firefox_102` · `firefox_104` · `firefox_105` · `firefox_106` | Firefox 102–106 |
| `firefox_108` · `firefox_110` | Firefox 108 · 110 |
| `firefox_117` · `firefox_120` · `firefox_123` | Firefox 117–123 |
| `firefox_132` · `firefox_133` · `firefox_135` | Firefox 132–135 |
| `firefox_146_PSK` | Firefox 146 with PSK |
| `firefox_147` · `firefox_147_PSK` | Firefox 147 (standard & PSK) |
| `firefox_148` | Firefox 148 |

### 🍏 Safari — 10 Profiles

| Identifier | Device |
|-----------|--------|
| `safari_15_6_1` | Safari 15.6.1 (macOS) |
| `safari_16_0` | Safari 16.0 (macOS) |
| `safari_ipad_15_6` | Safari 15.6 (iPadOS) |
| `safari_ios_15_5` · `safari_ios_15_6` | Safari iOS 15.5–15.6 |
| `safari_ios_16_0` · `safari_ios_17_0` | Safari iOS 16 · 17 |
| `safari_ios_18_0` · `safari_ios_18_5` | Safari iOS 18 · 18.5 |
| `safari_ios_26_0` | Safari iOS 26 |

### 🦁 Brave — 2 Profiles

| Identifier | Notes |
|-----------|-------|
| `brave_146` | Brave Browser 146 |
| `brave_146_PSK` | Brave 146 with PSK |

### 🎭 Opera — 3 Profiles

| Identifier |
|-----------|
| `opera_89` · `opera_90` · `opera_91` |

### 🤖 OkHttp (Android) — 7 Profiles

| Identifier |
|-----------|
| `okhttp4_android_7` — `okhttp4_android_13` |

### 📱 Mobile / App SDKs — 16 Profiles

| Category | Identifiers |
|----------|------------|
| Zalando | `zalando_android_mobile` · `zalando_ios_mobile` |
| Nike | `nike_ios_mobile` · `nike_android_mobile` |
| MMS | `mms_ios` · `mms_ios_1` · `mms_ios_2` · `mms_ios_3` |
| Mesh | `mesh_ios` · `mesh_ios_1` · `mesh_ios_2` · `mesh_android` · `mesh_android_1` · `mesh_android_2` |
| Confirmed | `confirmed_ios` · `confirmed_android` |

### ☁️ Cloudflare-specific — 1 Profile

| Identifier | Notes |
|-----------|-------|
| `cloudscraper` | Custom profile tuned for Cloudflare-protected sites |

---

## 🔧 Advanced Usage

### Full TLS controls at the top-level `Session`

`tls_client.Session` is Requests-compatible, but its public constructor keeps
the complete native TLS signature. IDE completion and `inspect.signature()`
therefore expose fingerprint, protocol, socket, proxy, certificate, cookie,
pool, and debug controls instead of showing only Requests arguments:

```python
import inspect
import tls_client

print(inspect.signature(tls_client.Session))
session = tls_client.Session(
    client_identifier="chrome_152",
    force_http1=True,
    disable_http3=True,
    random_tls_extension_order=False,
    tcp_mss=1460,
    tcp_ttl=64,
    max_connections_per_host=32,
    with_debug=True,
)
```

The same TLS keyword names are accepted by Requests-style calls (`get`,
`post`, `request`, and `execute_request`) for per-request overrides.

Unknown browser/fingerprint identifiers fail immediately with `ValueError`.
Use `SUPPORTED_CLIENT_IDENTIFIERS` to validate user input before creating a
session.

### Custom TLS Client (Full Control)

Set `custom_tls_client` with up to 26 fields to bypass `client_identifier` entirely:

```python
session = Session(custom_tls_client={
    "ja3_string": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
    "h2_settings": {"HEADER_TABLE_SIZE": 65536, "MAX_CONCURRENT_STREAMS": 1000},
    "h2_settings_order": ["HEADER_TABLE_SIZE", "MAX_CONCURRENT_STREAMS"],
    "pseudo_header_order": [":method", ":authority", ":scheme", ":path"],
    "connection_flow": 1048576,
    "key_share_curves": ["X25519", "P256"],
    "alpn_protocols": ["h2", "http/1.1"],
    "supported_versions": ["1.3", "1.2"],
    "stream_id": 3,
})
```

### Certificate Pinning

```python
session = Session(
    certificate_pinning_hosts={
        "example.com": ["sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]
    }
)
```

### Client Certificates (mTLS)

```python
session = Session(
    client_certificates=[{
        "cert_pem": open("client.crt", "rb").read(),
        "key_pem": open("client.key", "rb").read(),
    }]
)
```

### Fingerprint Presets (Coherent Browser Bundles)

A preset bundles the engine TLS profile, the per-OS coherent header block
(UA + Client Hints), the destination-aware header orders, the extension-shuffle
policy and the OS TCP fingerprint in one line:

```python
from tls_client import Session
from tls_client.fingerprints import apply, list_presets

print(len(list_presets()))            # 391 presets

session = Session()
apply(session, "chrome_150_windows")  # or chrome_99_linux, chrome_153_ios, ...
session.get("https://tls.peet.ws/api/all")
```

All 55 captured Chrome majors (99–153) ship as
`chrome_<major>_base`, `chrome_<major>_windows`, `_macos`, `_linux`,
`_android`, `_ios`, plus a bare `chrome_<major>` alias for the Windows
variant — and each per-OS variant derives a platform-coherent UA and TCP
fingerprint (Windows `TTL=128/window=64240`, Linux/macOS `TTL=64/window=65535`,
etc.). `header_order_for_dest(dest)` returns the header template for a
`Sec-Fetch-Dest` value.

Or directly: `Session(fingerprint="chrome_150_windows")`. Custom presets are
plain JSON with optional `based_on` inheritance:

```python
from tls_client.fingerprints import load_preset_file
load_preset_file("my_chrome.json")     # {"name": ..., "based_on": "chrome_152_windows", ...}
```

### Request Contexts (Sec-Fetch-*, Client Hints, Priority)

Describe *how* the request was initiated and the coherent header set is
derived (opt-in — without `context=` nothing changes):

```python
from tls_client.context import RequestContext

session.get(url, context=RequestContext.navigation(url, referrer=page_url))
session.post(api, context=RequestContext.xhr(api))
session.get(img, context=RequestContext.image(img))
```

### Trust Anchors (Chrome 152+, ABI 2) and ECH

```python
session = Session(custom_tls_client={
    "ja3_string": "...",
    "trust_anchors_payload": "0009080102030405060708",  # hex of the 0xCA34 payload
})

# Automatic ECH resolution over DoH (RFC 9460), cached per host:
from tls_client import ech
payload = ech.resolve("tls.peet.ws")
session = Session(custom_tls_client={
    "ja3_string": "...",
    "ech_candidate_payloads": ech.to_candidate_payloads(payload),
})
```

> `TLS_CLIENT_DOH_ENDPOINT` overrides the DoH server
> (e.g. `https://dns.alidns.com/resolve`) — useful on networks where
> `cloudflare-dns.com` is unreachable.

### TLS Debugging (Keylog) and Custom CA (ABI 2)

```python
session = Session(
    tls_keylog_path="keylog.txt",      # Wireshark TLS secrets
    root_ca_pem=open("corp-ca.pem", "rb").read(),
    disable_session_tickets=True,
)
```

### Deep Fingerprint Control (ABI 3)

Fine-grained, byte-level control over the handshake and the socket:

```python
session = Session(
    client_identifier="chrome_150",

    # Chromium shuffles the ClientHello extension order on *every*
    # handshake (unseeded), pinning GREASE / padding / pre_shared_key.
    #   0 = off (captured order)   1 = chrome
    #   2 = all extensions         3 = prefix (first N stay fixed)
    extension_permute_mode=1,
    extension_permute_prefix=0,     # only meaningful when mode=3

    # Suppress RFC 7540 PRIORITY frames / the HEADERS priority flag.
    h2_disable_priority_frames=False,

    # Pick the header order from the request's Sec-Fetch-Dest instead of
    # using one fixed order for every request.
    header_order_by_dest=True,
    header_order_dest=None,         # None = infer from Sec-Fetch-Dest

    # Deep TCP fingerprint. -1 (the default) leaves the profile's own
    # value untouched; 0 is a *real* value (DF cleared / TOS 0 / Nagle off).
    tcp_dont_fragment=-1,           # -1 unset · 0 clear DF · 1 set DF
    tcp_tos=-1,                     # -1 unset · 0..255
    tcp_no_delay=-1,                # -1 unset · 0 off · 1 on
    tcp_window_clamp=0,             # 0 unset · Linux TCP_WINDOW_CLAMP
    tcp_ip_id_mode="",              # "" unset · "random" · "zero" · "incremental"
)
```

Every parameter can also be set per request. On a shared library older than
ABI 3 these degrade to their defaults with a one-time `RuntimeWarning`
instead of failing the request — rebuild the native library to enable them.

Presets bundle all of the above automatically:

```python
from tls_client.fingerprints import apply

session = Session()
apply(session, "chrome_150_linux")   # identifier + headers + permute + TCP
```

### WebSocket (TLS-fingerprinted)

WebSocket connections reuse the same TLS fingerprint, connection pool and
header ordering as regular requests.  The handshake is forced to HTTP/1.1
(as the WebSocket upgrade requires it).

```python
from tls_client import WebSocket, TEXT, BINARY

# The fingerprint client is created from client_identifier (HTTP/1.1 enforced).
ws = WebSocket(url="wss://echo.websocket.events", client_identifier="chrome_131")

conn = ws.connect()                       # blocking handshake
conn.send_text("hello")                   # UTF-8 text frame
conn.send_binary(b"\x00\x01\x02")         # binary frame

message_type, data = conn.read_message()  # (TEXT=1, b"...") — blocks

conn.close()
ws.close()
```

`read_message()` returns a `(message_type, data)` tuple where `message_type` is
one of `TEXT`/`BINARY`/`CLOSE`/`PING`/`PONG`; it returns `None` on a clean
close.  Handshake headers and their wire order are controllable:

```python
ws = WebSocket(
    url="wss://example.com/ws",
    client_identifier="firefox_148",
    headers={"User-Agent": "MyBot/1.0", "Origin": "https://example.com"},
    header_order=["host", "upgrade", "connection", "user-agent"],
    handshake_timeout_milliseconds=10000,
)
```

### Build Tiers

A single full-fidelity build ships in each wheel — QUIC/HTTP-3 enabled and
the complete profile catalogue (there are no lite/nano tiers).

```bash
TLS_CLIENT_LIB=/path/to/tls-client.so   # optional: override the library path
```

`TLS_CLIENT_LIB` overrides the path entirely; by default the loader picks the
bundled native binary for the current OS/arch.

### Engine-Level HTTP/2 Realism (ABI 2.1)

```python
session = Session(
    hpack_indexing_policy="chrome",   # Chromium HPACK indexing behaviour
    h2_max_data_frame_size=14000,     # cap each DATA frame payload
    preface_ping_idle_ms=10000,       # PING before reuse after >=10s idle
    cookie_crumb=True,                # one Cookie field per cookie-pair
)
```

`cookie_crumb` splits the `Cookie` header into one field per cookie-pair on
the wire (Chromium "crumble") — observable as multiple `cookie:` fields by
HTTP/2 servers.

### Stream Response to Disk

```python
resp = session.stream_to_file(
    "GET", "https://tls.browserleaks.com/",
    output_path="/tmp/image.png"
)
print(resp.status_code)  # response metadata still available
```

### Per-Request Overrides

All `Session` constructor parameters can be overridden per request:

```python
s = Session(client_identifier="chrome_146")
# Override fingerprint for a single request
resp = s.get("https://tls.browserleaks.com/json", client_identifier="firefox_148")
```

---

## 🔬 Architecture

| Layer | Technology |
|-------|-----------|
| **Go Engine** | `bogdanfinn/tls-client` compiled as C shared library (`-buildmode=c-shared`) |
| **FFI Boundary** | Raw C structs via CFFI — no JSON serialization overhead |
| **Memory Safety** | `ffi.gc(resp, FreeResponse)` — Go panics surfaced as `RuntimeError` |
| **Python API** | `requests`-style `Session`, `Response`, `AsyncSession` |

---

## 📚 API Reference

### Session

| Method | Description |
|--------|-------------|
| `get(url, **kwargs)` | HTTP GET |
| `post(url, **kwargs)` | HTTP POST |
| `put(url, **kwargs)` | HTTP PUT |
| `delete(url, **kwargs)` | HTTP DELETE |
| `head(url, **kwargs)` | HTTP HEAD |
| `patch(url, **kwargs)` | HTTP PATCH |
| `execute_request(method, url, **kwargs)` | Generic request with full options |
| `typed_request(Request)` | Strongly-typed request |
| `stream_to_file(method, url, path)` | Stream response body to disk |
| `clear_client_pool()` | Close idle connections (static) |

### Response

| Property / Method | Description |
|-------------------|-------------|
| `status_code` | HTTP status code (int) |
| `headers` | Case-insensitive response headers |
| `content` | Raw bytes body |
| `text` | Decoded text body |
| `encoding` | Detected charset |
| `url` | Final URL after redirects |
| `cookies` | Requests cookie jar |
| `history` | Redirect response history |
| `request` | The originating `PreparedRequest` |
| `raw` | File-like buffered raw response |
| `used_protocol` | Protocol used (e.g. `HTTP/2.0`) |
| `ok` | `True` if `status_code < 400` |
| `reason` | HTTP reason phrase |
| `json()` | Parse body as JSON |
| `raise_for_status()` | Raise `tls_client.exceptions.HTTPError` on 4xx/5xx |
| `iter_content()` / `iter_lines()` | Iterate over buffered response data |

---

## 🔗 Credits

This project is a Python binding for **[bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client)**, which itself is built upon:

- [Carcraftz/fhttp](https://github.com/Carcraftz/fhttp)
- [Carcraftz/utls](https://github.com/Carcraftz/utls)
- [refraction-networking/utls](https://github.com/refraction-networking/utls)

The byte-exact fingerprint layer also draws on two Go fingerprinting projects whose
captured-clienthello techniques were studied as references:

- **[enetx/surf](https://github.com/enetx/surf)** — full `utls.ClientHelloSpec`
  profiles (trust-anchor `0xCA34`, ML-DSA/ML-KEM post-quantum, GREASE) for
  Chrome/Firefox.
- **[httpcloak](https://github.com/sardanioss/httpcloak)** — raw ClientHello /
  PSK-resumption replay, per-header HPACK representation and the high-entropy
  Client Hints model.

Thanks to the authors of all of the above for their open work.

---

## 📄 License

MIT — see [LICENSE](LICENSE).
