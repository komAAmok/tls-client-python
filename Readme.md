# tls-client-python

[![PyPI version](https://img.shields.io/pypi/v/tls-client-python)](https://pypi.org/project/tls-client-python/)
[![Python](https://img.shields.io/pypi/pyversions/tls-client-python)](https://pypi.org/project/tls-client-python/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**High-performance Python binding for [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client) via CFFI.**

Zero-copy FFI boundary, panic-proof, full TLS fingerprint control — with a familiar `requests`-style API.

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
| 🛡️ **Panic-proof** | All Go panics caught and surfaced as Python exceptions |
| ⚙️ **Custom TLS** | Full 26-field custom TLS client configuration |

---

## 📦 Installation

```bash
pip install tls-client-python
```

Pre-compiled binaries are included for **9 platforms** — no Go toolchain required.

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

---

## 🖥️ Supported Platforms

Pre-compiled native libraries are bundled for these platforms:

| OS | Architecture | Binary |
|----|-------------|--------|
| **Windows** | x86-64 | `tls-client-windows-amd64.dll` |
| **Windows** | x86 (32-bit) | `tls-client-windows-386.dll` |
| **macOS** | x86-64 | `tls-client-darwin-amd64.dylib` |
| **macOS** | ARM64 (Apple Silicon) | `tls-client-darwin-arm64.dylib` |
| **Linux** | x86-64 (glibc) | `tls-client-linux-amd64.so` |
| **Linux** | x86 (32-bit, glibc) | `tls-client-linux-386.so` |
| **Linux** | ARM64 | `tls-client-linux-arm64.so` |
| **Linux** | ARMv7 | `tls-client-linux-arm.so` |
| **Alpine Linux** | x86-64 (musl) | `tls-client-alpine-amd64.so` |

The correct binary is automatically selected at runtime. Override via `TLS_CLIENT_LIB` environment variable.

---

## 🎭 Supported Browser Profiles — 79 Identifiers

### 🌐 Chrome — 24 Profiles

| Identifier | Notes |
|-----------|-------|
| `chrome_103` — `chrome_112` | Chrome Stable 103–112 |
| `chrome_116_PSK` | Chrome 116 with PSK key exchange |
| `chrome_116_PSK_PQ` | Chrome 116 with PSK + Post-Quantum |
| `chrome_117` | Chrome 117 |
| `chrome_120` | Chrome 120 |
| `chrome_124` | Chrome 124 |
| `chrome_130_PSK` | Chrome 130 with PSK |
| `chrome_131` · `chrome_131_PSK` | Chrome 131 (standard & PSK) |
| `chrome_133` · `chrome_133_PSK` | Chrome 133 (standard & PSK) |
| `chrome_144` · `chrome_144_PSK` | Chrome 144 (standard & PSK) |
| `chrome_146` · `chrome_146_PSK` | Chrome 146 — **default** (standard & PSK) |

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
| `headers` | Response headers (dict of list) |
| `content` | Raw bytes body |
| `text` | Decoded text body |
| `encoding` | Detected charset |
| `url` | Final URL after redirects |
| `cookies` | Response cookies dict |
| `used_protocol` | Protocol used (e.g. `HTTP/2.0`) |
| `ok` | `True` if `status_code < 400` |
| `reason` | HTTP reason phrase |
| `json()` | Parse body as JSON |
| `raise_for_status()` | Raise `RuntimeError` on 4xx/5xx |

---

## 🔗 Credits

This project is a Python binding for **[bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client)**, which itself is built upon:

- [Carcraftz/fhttp](https://github.com/Carcraftz/fhttp)
- [Carcraftz/utls](https://github.com/Carcraftz/utls)
- [refraction-networking/utls](https://github.com/refraction-networking/utls)

---

## 📄 License

MIT — see [LICENSE](LICENSE).

---

## 🙏 Community

Join the [Discord server](https://discord.gg/7Ej9eJvHqk) for support and discussion.

---

<p align="center">
  <em>Powered by</em><br>
  <a href="https://jb.gg/OpenSource">
    <img src="https://resources.jetbrains.com/storage/products/company/brand/logos/jetbrains.svg" alt="JetBrains logo." height="40">
  </a>
</p>
