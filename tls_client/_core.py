#!/usr/bin/env python3
"""
tls_client._core  –  Low‑level CFFI binding for the Go tls-client engine.

Architecture
────────────
• Go shared library compiled with `-buildmode=c-shared` exports four
  symbols: ExecuteRequest, RequestAsync, FreeResponse, ClearClientPool.
• Sync path: ExecuteRequest blocks until completion, returns CResponseResult*.
  Python wraps it with `raw_res = ffi.gc(raw_res, lib.FreeResponse)` for
  automatic cleanup.
• Async path: RequestAsync deep-copies all C data into Go heap, dispatches a
  goroutine, and returns immediately.  The goroutine executes the HTTP request
  and calls a CFFI callback with (request_id, CResponseResult*).  Python
  unpacks the response in the callback, calls FreeResponse, and resolves an
  asyncio.Future via `loop.call_soon_threadsafe()`.  No thread pool — Python's
  event loop is never blocked.
• Response body is read via `ffi.buffer(res.body, res.body_len)[:]` for
  a single zero-copy-style memory view → Python bytes conversion.
• All temporary C allocations are anchored in a `keep_alive` list for the
  duration of the call, preventing premature GC and dangling pointers.

Classes
───────
• Session – synchronous client.  Supports `with` context manager.
• AsyncSession – asynchronous client using Go goroutines + CFFI callbacks.
  Compatible with uvloop / winloop for maximum event-loop performance.
"""

import asyncio
import ctypes
import os
import platform
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional
import hashlib

from tls_client._default_headers import DEFAULT_HEADERS

try:
    from typing import Literal, TypedDict
except ImportError:
    from typing_extensions import Literal, TypedDict  # Python 3.6–3.7

from typing_extensions import TypeAlias  # Python <3.10


# ---------------------------------------------------------------------------
# Supported TLS client identifiers — literal type for IDE autocompletion
# ---------------------------------------------------------------------------

ClientIdentifiers: TypeAlias = Literal[
    # ── Chrome ──
    "chrome_103", "chrome_104", "chrome_105", "chrome_106",
    "chrome_107", "chrome_108", "chrome_109", "chrome_110",
    "chrome_111", "chrome_112",
    "chrome_116_PSK", "chrome_116_PSK_PQ",
    "chrome_117", "chrome_120", "chrome_124",
    "chrome_130_PSK",
    "chrome_131", "chrome_131_PSK",
    "chrome_133", "chrome_133_PSK",
    "chrome_144", "chrome_144_PSK",
    "chrome_146", "chrome_146_PSK",
        # ── Brave ──
    "brave_146", "brave_146_PSK",
        # ── Safari ──
    "safari_15_6_1", "safari_16_0",
    "safari_ipad_15_6",
    "safari_ios_15_5", "safari_ios_15_6", "safari_ios_16_0",
    "safari_ios_17_0",
    "safari_ios_18_0", "safari_ios_18_5",
    "safari_ios_26_0",
        # ── Firefox ──
    "firefox_102", "firefox_104", "firefox_105", "firefox_106",
    "firefox_108", "firefox_110",
    "firefox_117", "firefox_120", "firefox_123",
    "firefox_132", "firefox_133", "firefox_135",
    "firefox_146_PSK",
    "firefox_147", "firefox_147_PSK",
    "firefox_148",
        # ── Opera ──
    "opera_89", "opera_90", "opera_91",
        # ── Zalando ──
    "zalando_android_mobile", "zalando_ios_mobile",
        # ── Nike ──
    "nike_ios_mobile", "nike_android_mobile",
        # ── Cloudflare ──
    "cloudscraper",
        # ── MMS ──
    "mms_ios", "mms_ios_1", "mms_ios_2", "mms_ios_3",
        # ── Mesh ──
    "mesh_ios", "mesh_ios_1", "mesh_ios_2",
    "mesh_android", "mesh_android_1", "mesh_android_2",
        # ── Confirmed ──
    "confirmed_ios", "confirmed_android",
        # ── OkHttp ──
    "okhttp4_android_7", "okhttp4_android_8", "okhttp4_android_9",
    "okhttp4_android_10", "okhttp4_android_11",
    "okhttp4_android_12", "okhttp4_android_13",
]


# ---------------------------------------------------------------------------
# 强类型请求对象 ─ 提供 IDE 自动补全
# Strongly-typed request object — provides IDE autocompletion
# ---------------------------------------------------------------------------

class Request(TypedDict, total=False):
    """强类型请求对象，提供 IDE 自动补全。

    Strongly-typed request object for IDE autocompletion.
    """

    method: str
    """HTTP 方法，如 ``"GET"``、``"POST"``。在 :meth:`Session.typed_request` 中必填。

    HTTP method, e.g. ``"GET"``, ``"POST"``. Required in :meth:`Session.typed_request`.
    """
    url: str
    """请求 URL。在 :meth:`Session.typed_request` 中必填。

    Request URL. Required in :meth:`Session.typed_request`.
    """
    headers: Optional[Dict[str, str]]
    """请求头字典。

    Request headers dict.
    """
    header_order: Optional[List[str]]
    """请求头发送顺序列表。

    Header send-order list.
    """
    body: Optional[bytes]
    """请求体原始字节串。

    Request body as raw bytes.
    """
    client_identifier: Optional[str]
    """TLS 指纹标识。

    TLS fingerprint identifier.
    """
    timeout: Optional[int]
    """超时时间（秒）。

    Timeout in seconds.
    """
    timeout_milliseconds: Optional[int]
    """超时时间（毫秒）。

    Timeout in milliseconds.
    """
    follow_redirects: Optional[bool]
    """是否跟随重定向。

    Whether to follow redirects.
    """
    verify: Optional[bool]
    """是否验证 TLS 证书。

    Whether to verify the TLS certificate.
    """
    force_http1: Optional[bool]
    """是否强制 HTTP/1.1。

    Whether to force HTTP/1.1.
    """
    random_tls_extension_order: Optional[bool]
    """是否随机 TLS 扩展顺序。

    Whether to randomise TLS extension order.
    """
    with_protocol_racing: Optional[bool]
    """是否启用协议竞速。

    Whether to enable protocol racing.
    """
    server_name_overwrite: Optional[str]
    """SNI 主机名覆盖。

    SNI hostname override.
    """
    request_host_override: Optional[str]
    """Host 请求头覆盖。

    Host header override.
    """
    proxy: Optional[str]
    """代理 URL。

    Proxy URL.
    """
    local_address: Optional[str]
    """本地绑定地址。

    Local bind address.
    """
    pseudo_header_order: Optional[List[str]]
    """HTTP/2 伪头顺序。

    HTTP/2 pseudo-header order.
    """
    h3_pseudo_header_order: Optional[List[str]]
    """HTTP/3 伪头顺序。

    HTTP/3 pseudo-header order.
    """
    max_idle_connections: Optional[int]
    """全局最大空闲连接数。

    Global max idle connections.
    """
    max_idle_connections_per_host: Optional[int]
    """每 Host 最大空闲连接数。

    Max idle connections per host.
    """
    max_connections_per_host: Optional[int]
    """每 Host 最大总连接数。

    Max total connections per host.
    """
    disable_keep_alives: Optional[bool]
    """是否禁用 Keep-Alive。

    Whether to disable Keep-Alive.
    """
    disable_compression: Optional[bool]
    """是否禁用响应解压。

    Whether to disable decompression.
    """
    idle_conn_timeout_seconds: Optional[int]
    """空闲连接超时（秒）。

    Idle connection timeout (seconds).
    """
    max_response_header_bytes: Optional[int]
    """响应头最大字节数。

    Max response header bytes.
    """
    write_buffer_size: Optional[int]
    """写缓冲区大小。

    Write buffer size.
    """
    read_buffer_size: Optional[int]
    """读缓冲区大小。

    Read buffer size.
    """
    allow_empty_cookies: Optional[bool]
    """是否允许空 Cookie。

    Whether to allow empty cookies.
    """
    without_cookie_jar: Optional[bool]
    """是否禁用 Cookie Jar。

    Whether to disable Cookie Jar.
    """
    disable_http3: Optional[bool]
    """是否禁用 HTTP/3。

    Whether to disable HTTP/3.
    """
    disable_ipv4: Optional[bool]
    """是否禁用 IPv4。

    Whether to disable IPv4.
    """
    disable_ipv6: Optional[bool]
    """是否禁用 IPv6。

    Whether to disable IPv6.
    """
    catch_panics: Optional[bool]
    """是否捕获 Go panic。

    Whether to catch Go panics.
    """
    with_debug: Optional[bool]
    """是否启用调试日志。

    Whether to enable debug logging.
    """
    default_headers: Optional[Dict[str, str]]
    """默认请求头字典，每次请求自动附加。

    Default headers dict, automatically added to every request.
    """
    connect_headers: Optional[Dict[str, str]]
    """代理 CONNECT 隧道请求头字典。

    Proxy CONNECT tunnel headers dict.
    """
    certificate_pinning_hosts: Optional[Dict[str, List[str]]]
    """SSL 证书固定字典，格式为 ``{host: [pin1, pin2, ...]}``。

    SSL certificate pinning dict, format ``{host: [pin1, pin2, ...]}``.
    """
    with_default_bad_pin_handler: Optional[bool]
    """是否在证书固定失败时调用默认 Bad-Pin 处理器。

    Whether to invoke the default bad-pin handler on pin mismatch.
    """
    request_cookies: Optional[Dict[str, str]]
    """预置 Cookie 字典，在发送请求前注入到 Cookie Jar。

    Pre-populated cookie dict, injected into the Cookie Jar before sending.
    """
    custom_tls_client: Optional[Dict[str, Any]]
    """完全自定义的 TLS 客户端配置字典。

    Fully custom TLS client configuration dict.

    包含 JA3 字符串、密码套件、ECH、ALPN、HTTP/2/3 设置等 26 个字段。
    设置后将忽略 ``client_identifier``。

    Contains JA3 string, cipher suites, ECH, ALPN, HTTP/2/3 settings, etc.
    (26 fields).  When set, ``client_identifier`` is ignored.
    """
    client_certificates: Optional[List[Dict[str, bytes]]]
    """客户端证书列表，用于 mTLS 双向认证。

    每个元素为 ``{'cert_pem': bytes, 'key_pem': bytes}``。

    Client certificate list for mTLS mutual authentication.

    Each element is ``{'cert_pem': bytes, 'key_pem': bytes}``.
    """


# ---------------------------------------------------------------------------
# Response  –  requests‑style response object
# ---------------------------------------------------------------------------

class Response:
    """HTTP 响应对象，兼容 requests 库风格。

    A requests‑compatible HTTP response object.

    Attributes
    ----------
    status_code : int
        HTTP 状态码 / HTTP status code.
    headers : dict
        响应头字典 / Response headers.
    content : bytes
        原始响应体字节串 / Raw response body as bytes.
    text : str
        已解码的响应体文本 / Decoded response body text.
    encoding : str
        检测到的字符编码 / Detected charset encoding.
    url : str or None
        最终请求 URL（重定向后）/ Final URL after redirects.
    cookies : dict
        响应 Cookie 字典 / Response cookies dict.
    used_protocol : str or None
        实际使用的 HTTP 协议版本 / HTTP protocol version used.
    """

    __slots__ = (
        "_status_code",
        "_headers",
        "_content",
        "_text",
        "_encoding",
        "_url",
        "_cookies",
        "_used_protocol",
    )

    def __init__(
        self,
        status_code: int,
        headers: Dict[str, List[str]],
        content: bytes,
        text: str,
        encoding: str,
        url: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        used_protocol: Optional[str] = None,
    ) -> None:
        self._status_code = status_code
        self._headers = headers
        self._content = content
        self._text = text
        self._encoding = encoding
        self._url = url
        self._cookies = cookies or {}
        self._used_protocol = used_protocol

    # -- read‑only properties ----------------------------------------------

    @property
    def status_code(self) -> int:
        """HTTP 状态码 / HTTP status code."""
        return self._status_code

    @property
    def headers(self) -> Dict[str, List[str]]:
        """响应头字典 / Response headers."""
        return self._headers

    @property
    def content(self) -> bytes:
        """原始响应体字节串 / Raw bytes body."""
        return self._content

    @property
    def text(self) -> str:
        """已解码的响应体文本 / Decoded text body."""
        return self._text

    @property
    def encoding(self) -> str:
        """文本编码 / Text encoding."""
        return self._encoding

    @property
    def url(self) -> Optional[str]:
        """最终请求 URL（重定向后）/ Final URL after redirects."""
        return self._url

    @property
    def cookies(self) -> Dict[str, str]:
        """响应 Cookie 字典 / Response cookies dict."""
        return self._cookies

    @property
    def used_protocol(self) -> Optional[str]:
        """使用的 HTTP 协议版本 / HTTP protocol version (e.g. ``"HTTP/2.0"``)."""
        return self._used_protocol

    @property
    def ok(self) -> bool:
        """状态码 < 400 时为 ``True``。  /  ``True`` if status_code < 400."""
        return self._status_code < 400

    @property
    def reason(self) -> str:
        """HTTP 状态文本 / HTTP reason phrase."""
        from http.client import responses
        return responses.get(self._status_code, "Unknown")

    # -- public methods ----------------------------------------------------

    def json(self, **kwargs: Any) -> Any:
        """解析 JSON 响应体。  /  Parse response body as JSON.

        Parameters are forwarded to :func:`json.loads`.
        """
        import json
        return json.loads(self._text, **kwargs)

    def raise_for_status(self) -> None:
        """若状态码 ≥ 400，抛出 :exc:`RuntimeError`。

        Raise :exc:`RuntimeError` if the status code indicates an error
        (4xx client error or 5xx server error).
        """
        if self._status_code >= 400:
            raise RuntimeError(
                f"{self._status_code} {self.reason} for url: {self._url or '(unknown)'}"
            )

    # -- dunder methods ----------------------------------------------------

    def __bool__(self) -> bool:
        """``bool(resp)`` → ``resp.ok``。"""
        return self.ok

    def __repr__(self) -> str:
        return f"<Response [{self._status_code}]>"

    def __str__(self) -> str:
        return self.__repr__()


# ---------------------------------------------------------------------------
# CFFI cdef – must stay byte‑identical with main.go `import "C"` block
# ---------------------------------------------------------------------------

CDEF = """
typedef struct {
    const char* key;
    const char* value;
} HttpHeader;

typedef struct {
    const char* host;
    const char** pins;
    int   pins_len;
} PinEntry;

typedef struct {
    unsigned int streamDep;
    int          exclusive;
    unsigned char weight;
} PriorityParam;

typedef struct {
    PriorityParam priorityParam;
    unsigned int  streamID;
} PriorityFrame;

typedef struct {
    const char* kdfId;
    const char* aeadId;
} CandidateCipherSuite;

typedef struct {
    const char* cert_pem;
    int   cert_pem_len;
    const char* key_pem;
    int   key_pem_len;
} ClientCertificate;

typedef struct {
    const char** h2_settings_keys;
    unsigned int* h2_settings_values;
    int   h2_settings_len;
    const char** h2_settings_order;
    int   h2_settings_order_len;
    const char** h3_settings_keys;
    unsigned long long* h3_settings_values;
    int   h3_settings_len;
    const char** h3_settings_order;
    int   h3_settings_order_len;
    const char** h3_pseudo_header_order;
    int   h3_pseudo_header_order_len;
    PriorityParam* header_priority;
    const char** cert_compression_algos;
    int   cert_compression_algos_len;
    const char* ja3_string;
    const char** key_share_curves;
    int   key_share_curves_len;
    const char** alpn_protocols;
    int   alpn_protocols_len;
    const char** alps_protocols;
    int   alps_protocols_len;
    unsigned short* ech_candidate_payloads;
    int   ech_candidate_payloads_len;
    CandidateCipherSuite* ech_candidate_cipher_suites;
    int   ech_candidate_cipher_suites_len;
    PriorityFrame* priority_frames;
    int   priority_frames_len;
    const char** pseudo_header_order;
    int   pseudo_header_order_len;
    const char** supported_delegated_credentials_algorithms;
    int   supported_delegated_credentials_algorithms_len;
    const char** supported_signature_algorithms;
    int   supported_signature_algorithms_len;
    const char** supported_versions;
    int   supported_versions_len;
    unsigned int   connection_flow;
    unsigned short record_size_limit;
    unsigned int   stream_id;
    unsigned int   h3_priority_param;
    int   h3_send_grease_frames;
    int   allow_http;
} CustomTlsClient;

typedef struct {
    const char* method;
    const char* url;
    const char* body;
    int   body_len;
    const char* proxy;
    const char* client_identifier;
    HttpHeader* headers;
    int   headers_len;
    const char** header_order;
    int   header_order_len;
    const char** pseudo_header_order;
    int   pseudo_header_order_len;
    const char** h3_pseudo_header_order;
    int   h3_pseudo_header_order_len;
    int   timeout_seconds;
    int   timeout_milliseconds;
    int   follow_redirects;
    int   insecure_skip_verify;
    int   force_http1;
    int   with_random_tls_extension_order;
    int   with_protocol_racing;
    const char* server_name_overwrite;
    const char* request_host_override;
    const char* local_address;
    int   max_idle_connections;
    int   max_idle_connections_per_host;
    int   max_connections_per_host;
    int   max_response_header_bytes;
    int   write_buffer_size;
    int   read_buffer_size;
    int   idle_conn_timeout_seconds;
    int   disable_keep_alives;
    int   disable_compression;
    int   allow_empty_cookies;
    int   disable_http3;
    int   disable_ipv4;
    int   disable_ipv6;
    int   without_cookie_jar;
    int   catch_panics;
    int   with_debug;
    const char* stream_output_path;
    int   stream_output_block_size;
    const char* stream_output_eof_symbol;
    HttpHeader* default_headers;
    int   default_headers_len;
    HttpHeader* connect_headers;
    int   connect_headers_len;
    PinEntry* certificate_pinning_hosts;
    int   certificate_pinning_hosts_len;
    int   with_default_bad_pin_handler;
    HttpHeader* request_cookies;
    int   request_cookies_len;
    ClientCertificate* client_certificates;
    int   client_certificates_len;
    CustomTlsClient* custom_tls_client;
    const char* cache_key_hash;
} RequestOptions;

typedef struct {
    int   status_code;
    char* body;
    int   body_len;
    char* err_msg;
    char* target_url;
    char* used_protocol;
    HttpHeader* response_headers;
    int   response_headers_len;
    HttpHeader* cookies;
    int   cookies_len;
    char* _resp_strings;
} ResponseResult;

ResponseResult* ExecuteRequest(RequestOptions* opts);
void           FreeResponse(ResponseResult* res);
void           ClearClientPool(void);

void           SetPoolTTL(int seconds);
void           SetPoolScanInterval(int seconds);

typedef void (*async_callback_fn)(uintptr_t request_id, ResponseResult* response);
int            RequestAsync(RequestOptions* opts, uintptr_t request_id, async_callback_fn cb);
"""

# ---------------------------------------------------------------------------
# Platform detection & shared‑library loading
# ---------------------------------------------------------------------------

def _find_library() -> str:
    """定位平台对应的动态链接库。

    搜索顺序：
    1. 读取 ``TLS_CLIENT_LIB`` 环境变量（显式用户覆盖）。
    2. 寻找包目录内 ``tls_client/bin/`` 下的平台专属统一命名文件。
    3. 寻找同级开发目录 ``dist/`` 下的文件。

    若未找到任何匹配文件，抛出 :exc:`FileNotFoundError`。
    """
    # 1. 环境变量显式覆盖
    env_lib = os.environ.get("TLS_CLIENT_LIB")
    if env_lib:
        p = Path(env_lib)
        if p.exists():
            return str(p)
        raise FileNotFoundError(
            f"TLS_CLIENT_LIB is set to '{env_lib}' but the file does not exist."
        )

    # 2. 根据系统平台直接映射标准统一文件名
    if sys.platform == "win32":
        name = "tls-client.dll"
    elif sys.platform == "darwin":
        name = "tls-client.dylib"
    else:
        name = "tls-client.so"

    here = Path(__file__).resolve().parent

    # 3. 寻找分平台 Wheel 安装后的专属内置路径
    bundled = here / "bin" / name
    if bundled.exists():
        return str(bundled)

    # 4. 本地开发调试路径
    dev = here / "dist" / name
    if dev.exists():
        return str(dev)

    # 详细的异常诊断提示
    parts = [
        f"Cannot locate shared library '{name}' inside the package.",
        "",
        f"  Searched:  {bundled}",
        f"             {dev}",
        "",
        "  If you are developing locally, ensure the shared library is compiled and placed",
        "  in either 'tls_client/bin/' or 'tls_client/dist/'.",
        "  Alternatively, set the 'TLS_CLIENT_LIB' environment variable to point directly to your binary."
    ]
    raise FileNotFoundError("\n".join(parts))


def _load_ffi():
    """Lazy‑import cffi so the wrapper is importable without it installed."""
    from cffi import FFI

    ffi = FFI()
    ffi.cdef(CDEF)
    libpath = _find_library()

    try:
        lib = ffi.dlopen(libpath)
    except OSError as exc:
        raise OSError(
            f"Shared library at '{libpath}' failed to load. "
            f"The binary may be corrupt, built for a different architecture, "
            f"or missing system dependencies.\n"
            f"Underlying error: {exc}"
        ) from exc

    return ffi, lib


# Global singletons – initialised on first use
_ffi = None
_lib = None
_ffi_lock = threading.Lock()


def _get_ffi():
    global _ffi, _lib
    if _ffi is None:
        with _ffi_lock:
            if _ffi is None:
                _ffi, _lib = _load_ffi()
    return _ffi, _lib


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _charset_from_content_type(content_type: str) -> str:
    """Extract charset from Content-Type header, default to ``"utf-8"``.

    Mirrors ``golang.org/x/net/html/charset.NewReader`` behaviour.
    """
    if not content_type:
        return "utf-8"
    # Parse 'text/html; charset=gbk' → 'gbk'
    for part in content_type.lower().split(";"):
        part = part.strip()
        if part.startswith("charset=") or part.startswith("charset ="):
            enc = part.split("=", 1)[1].strip().strip('"').strip("'")
            if enc:
                return enc
    return "utf-8"


def _c_string(ffi, value: Optional[str]) -> Any:
    """Allocate a null‑terminated C string (or ``ffi.NULL``)."""
    if value is None:
        return ffi.NULL
    return ffi.new("char[]", value.encode("utf-8"))


def _build_headers(ffi, headers: Optional[Dict[str, str]], keep_alive: list):
    """Convert a Python dict → C HttpHeader[].  Returns ``(ptr, length)``."""
    if not headers:
        return ffi.NULL, 0

    n = len(headers)
    arr = ffi.new("HttpHeader[]", n)
    keep_alive.append(arr)

    for i, (k, v) in enumerate(headers.items()):
        ck = ffi.new("char[]", k.encode("utf-8"))
        cv = ffi.new("char[]", v.encode("utf-8"))
        keep_alive.extend([ck, cv])
        arr[i].key = ck
        arr[i].value = cv

    return arr, n


def _build_string_array(ffi, items: Optional[List[str]], keep_alive: list):
    """Convert a Python list[str] → C const char**.  Returns ``(ptr, length)``."""
    if not items:
        return ffi.NULL, 0

    n = len(items)
    arr = ffi.new("const char*[]", n)
    keep_alive.append(arr)

    for i, s in enumerate(items):
        cs = ffi.new("char[]", s.encode("utf-8"))
        keep_alive.append(cs)
        arr[i] = cs

    return arr, n


def _build_pin_entries(ffi, pins: Optional[Dict[str, List[str]]], keep_alive: list):
    """Convert a Python dict[str, list[str]] → C PinEntry[].  Returns ``(ptr, length)``."""
    if not pins:
        return ffi.NULL, 0

    n = len(pins)
    arr = ffi.new("PinEntry[]", n)
    keep_alive.append(arr)

    for i, (host, pin_list) in enumerate(pins.items()):
        ch = ffi.new("char[]", host.encode("utf-8"))
        keep_alive.append(ch)
        arr[i].host = ch

        if pin_list:
            pn = len(pin_list)
            parr = ffi.new("const char*[]", pn)
            keep_alive.append(parr)
            for j, pin in enumerate(pin_list):
                cp = ffi.new("char[]", pin.encode("utf-8"))
                keep_alive.append(cp)
                parr[j] = cp
            arr[i].pins = parr
            arr[i].pins_len = pn
        else:
            arr[i].pins = ffi.NULL
            arr[i].pins_len = 0

    return arr, n


def _build_client_certificates(ffi, certs: Optional[List[Dict[str, bytes]]], keep_alive: list):
    """Convert a Python list[dict] → C ClientCertificate[].  Returns ``(ptr, length)``.

    Each dict must have ``"cert_pem"`` and ``"key_pem"`` keys with bytes values.
    """
    if not certs:
        return ffi.NULL, 0

    n = len(certs)
    arr = ffi.new("ClientCertificate[]", n)
    keep_alive.append(arr)

    for i, c in enumerate(certs):
        cert_bytes = c.get("cert_pem", b"")
        key_bytes = c.get("key_pem", b"")

        cc = ffi.new("char[]", cert_bytes)
        ck = ffi.new("char[]", key_bytes)
        keep_alive.extend([cc, ck])
        arr[i].cert_pem = cc
        arr[i].cert_pem_len = len(cert_bytes)
        arr[i].key_pem = ck
        arr[i].key_pem_len = len(key_bytes)

    return arr, n


def _build_custom_tls_client(ffi, cfg: Optional[Dict[str, Any]], keep_alive: list):
    """Convert a Python dict → C CustomTlsClient*.  Returns ``ffi.NULL`` when
    *cfg* is None or empty."""
    if not cfg:
        return ffi.NULL

    ctc = ffi.new("CustomTlsClient *")
    keep_alive.append(ctc)

    # JA3 string
    ja3 = _c_string(ffi, cfg.get("ja3_string"))
    if ja3 != ffi.NULL:
        keep_alive.append(ja3)
    ctc.ja3_string = ja3

    # Simple scalar fields
    ctc.connection_flow = cfg.get("connection_flow", 0)
    ctc.record_size_limit = cfg.get("record_size_limit", 0)
    ctc.stream_id = cfg.get("stream_id", 0)
    ctc.h3_priority_param = cfg.get("h3_priority_param", 0)
    ctc.h3_send_grease_frames = 1 if cfg.get("h3_send_grease_frames") else 0
    ctc.allow_http = 1 if cfg.get("allow_http") else 0

    # String arrays
    ctc.h2_settings_order, ctc.h2_settings_order_len = _build_string_array(
        ffi, cfg.get("h2_settings_order"), keep_alive
    )
    ctc.h3_settings_order, ctc.h3_settings_order_len = _build_string_array(
        ffi, cfg.get("h3_settings_order"), keep_alive
    )
    ctc.h3_pseudo_header_order, ctc.h3_pseudo_header_order_len = _build_string_array(
        ffi, cfg.get("h3_pseudo_header_order"), keep_alive
    )
    ctc.cert_compression_algos, ctc.cert_compression_algos_len = _build_string_array(
        ffi, cfg.get("cert_compression_algos"), keep_alive
    )
    ctc.key_share_curves, ctc.key_share_curves_len = _build_string_array(
        ffi, cfg.get("key_share_curves"), keep_alive
    )
    ctc.alpn_protocols, ctc.alpn_protocols_len = _build_string_array(
        ffi, cfg.get("alpn_protocols"), keep_alive
    )
    ctc.alps_protocols, ctc.alps_protocols_len = _build_string_array(
        ffi, cfg.get("alps_protocols"), keep_alive
    )
    ctc.pseudo_header_order, ctc.pseudo_header_order_len = _build_string_array(
        ffi, cfg.get("pseudo_header_order"), keep_alive
    )
    ctc.supported_delegated_credentials_algorithms, ctc.supported_delegated_credentials_algorithms_len = _build_string_array(
        ffi, cfg.get("supported_delegated_credentials_algorithms"), keep_alive
    )
    ctc.supported_signature_algorithms, ctc.supported_signature_algorithms_len = _build_string_array(
        ffi, cfg.get("supported_signature_algorithms"), keep_alive
    )
    ctc.supported_versions, ctc.supported_versions_len = _build_string_array(
        ffi, cfg.get("supported_versions"), keep_alive
    )

    # H2/H3 settings key-value pairs
    h2_settings = cfg.get("h2_settings")
    if h2_settings:
        n = len(h2_settings)
        keys = ffi.new("const char*[]", n)
        vals = ffi.new("unsigned int[]", n)
        keep_alive.extend([keys, vals])
        for i, (k, v) in enumerate(h2_settings.items()):
            ck = ffi.new("char[]", k.encode("utf-8"))
            keep_alive.append(ck)
            keys[i] = ck
            vals[i] = v
        ctc.h2_settings_keys = keys
        ctc.h2_settings_values = vals
        ctc.h2_settings_len = n

    h3_settings = cfg.get("h3_settings")
    if h3_settings:
        n = len(h3_settings)
        keys = ffi.new("const char*[]", n)
        vals = ffi.new("unsigned long long[]", n)
        keep_alive.extend([keys, vals])
        for i, (k, v) in enumerate(h3_settings.items()):
            ck = ffi.new("char[]", k.encode("utf-8"))
            keep_alive.append(ck)
            keys[i] = ck
            vals[i] = v
        ctc.h3_settings_keys = keys
        ctc.h3_settings_values = vals
        ctc.h3_settings_len = n

    # ECH candidate payloads
    ech_payloads = cfg.get("ech_candidate_payloads")
    if ech_payloads:
        n = len(ech_payloads)
        arr = ffi.new("unsigned short[]", ech_payloads)
        keep_alive.append(arr)
        ctc.ech_candidate_payloads = arr
        ctc.ech_candidate_payloads_len = n

    # ECH candidate cipher suites
    ech_suites = cfg.get("ech_candidate_cipher_suites")
    if ech_suites:
        n = len(ech_suites)
        arr = ffi.new("CandidateCipherSuite[]", n)
        keep_alive.append(arr)
        for i, suite in enumerate(ech_suites):
            kdf = _c_string(ffi, suite.get("kdfId"))
            aead = _c_string(ffi, suite.get("aeadId"))
            if kdf != ffi.NULL:
                keep_alive.append(kdf)
            if aead != ffi.NULL:
                keep_alive.append(aead)
            arr[i].kdfId = kdf
            arr[i].aeadId = aead
        ctc.ech_candidate_cipher_suites = arr
        ctc.ech_candidate_cipher_suites_len = n

    # Priority frames
    pri_frames = cfg.get("priority_frames")
    if pri_frames:
        n = len(pri_frames)
        arr = ffi.new("PriorityFrame[]", n)
        keep_alive.append(arr)
        for i, pf in enumerate(pri_frames):
            pp = pf.get("priorityParam", {})
            arr[i].priorityParam.streamDep = pp.get("streamDep", 0)
            arr[i].priorityParam.exclusive = 1 if pp.get("exclusive") else 0
            arr[i].priorityParam.weight = pp.get("weight", 0)
            arr[i].streamID = pf.get("streamID", 0)
        ctc.priority_frames = arr
        ctc.priority_frames_len = n

    # Header priority (single optional struct)
    hp = cfg.get("header_priority")
    if hp:
        chp = ffi.new("PriorityParam *")
        keep_alive.append(chp)
        chp.streamDep = hp.get("streamDep", 0)
        chp.exclusive = 1 if hp.get("exclusive") else 0
        chp.weight = hp.get("weight", 0)
        ctc.header_priority = chp

    return ctc


# ---------------------------------------------------------------------------
# Cache-key pre-computation — mirrors Go's buildCacheKey format EXACTLY.
# Python computes the SHA-256 hash natively so Go can skip 50–200 C.GoString()
# CGO calls on every cache hit.  The hash is passed to Go via
# RequestOptions.cache_key_hash — if non-empty, Go uses it directly for
# clientPool.Load, bypassing buildCacheKey entirely.
#
# WARNING: This function must produce byte-for-byte identical output to
# Go's buildCacheKey in cffi_binding/main.go.  If either side drifts,
# cache entries will be stored under different keys, causing silent
# cache poisoning (duplicate clients).  The test_cache_key_parity.py
# test catches format drift BEFORE it reaches production.
# ---------------------------------------------------------------------------

def _compute_cache_key_hash(r: dict) -> str:
    """Return the SHA-256 hex digest of resolved config values.

    The format matches Go's buildCacheKey exactly — same field order,
    same separators, same sort order for maps, same hex encoding.

    FORMAT VERSION: 1
    If you change the hash format below, increment the version AND update
    Go's buildCacheKey / buildCacheKeyFromConfig in cffi_binding/main.go
    and the corresponding test in test_cache_key_parity.py.  Format drift
    causes silent cache poisoning (different keys → duplicate clients).
    """
    h = hashlib.sha256()

    ci = r.get("client_identifier") or ""
    px = r.get("proxy") or ""
    sn = r.get("server_name_overwrite") or ""
    la = r.get("local_address") or ""

    # ── 22 int fields (matching Go's 22 %%d format verbs) ──────────────
    main = (
        f"{ci}|{px}|{sn}|{la}|"
        f"{r['insecure_skip_verify']}|{r['force_http1']}|"
        f"{r['with_random_tls_extension_order']}|{r['with_protocol_racing']}|"
        f"{r['max_idle_connections']}|{r['max_idle_connections_per_host']}|"
        f"{r['max_connections_per_host']}|{r['max_response_header_bytes']}|"
        f"{r['write_buffer_size']}|{r['read_buffer_size']}|"
        f"{r['idle_conn_timeout_seconds']}|{r['disable_keep_alives']}|"
        f"{r['disable_compression']}|{r['disable_http3']}|"
        f"{r['disable_ipv4']}|{r['disable_ipv6']}|{r['follow_redirects']}|"
        f"{r['without_cookie_jar']}|{r['allow_empty_cookies']}|"
        f"{r['with_default_bad_pin_handler']}|"
        f"{r['timeout_seconds']}|{r['timeout_milliseconds']}"
    )
    h.update(main.encode("utf-8"))

    # ── Pseudo-header orders ──────────────────────────────────────────
    ph = r.get("pseudo_header_order")
    if ph:
        for s in ph:
            h.update(f":{s}".encode("utf-8"))
    else:
        h.update(b":<default>")

    h3ph = r.get("h3_pseudo_header_order")
    if h3ph:
        for s in h3ph:
            h.update(f"#{s}".encode("utf-8"))
    else:
        h.update(b"#<default>")

    # ── Default / connect headers (sorted by key) ─────────────────────
    for prefix, key in [("~dh:", "default_headers"), ("~ch:", "connect_headers")]:
        headers = r.get(key)
        if headers:
            for k in sorted(headers.keys()):
                h.update(f"{prefix}{k}={headers[k]}".encode("utf-8"))

    # ── Certificate pinning (sorted by host) ──────────────────────────
    cp = r.get("certificate_pinning_hosts")
    if cp:
        for host in sorted(cp.keys()):
            h.update(f"^cp:{host}=".encode("utf-8"))
            for pin in cp[host]:
                h.update(f"{pin},".encode("utf-8"))

    # ── Client certificates ───────────────────────────────────────────
    cc = r.get("client_certificates")
    if cc:
        for cert in cc:
            cert_pem = cert.get("cert_pem", b"")
            key_pem = cert.get("key_pem", b"")
            h.update(f"|cc:{hashlib.sha256(cert_pem).hexdigest()}".encode("utf-8"))
            h.update(f"|ck:{hashlib.sha256(key_pem).hexdigest()}".encode("utf-8"))

    # ── Custom TLS client profile ─────────────────────────────────────
    ctc = r.get("custom_tls_client")
    if ctc:
        h.update(f"|ja3={ctc.get('ja3_string', '')}".encode("utf-8"))
        h.update(f"|cf={ctc.get('connection_flow', 0)}".encode("utf-8"))
        h.update(f"|rsl={ctc.get('record_size_limit', 0)}".encode("utf-8"))
        h.update(f"|sid={ctc.get('stream_id', 0)}".encode("utf-8"))
        h.update(f"|h3pp={ctc.get('h3_priority_param', 0)}".encode("utf-8"))
        h.update(f"|h3sgf={1 if ctc.get('h3_send_grease_frames') else 0}".encode("utf-8"))
        h.update(f"|ah={1 if ctc.get('allow_http') else 0}".encode("utf-8"))

        str_arrays = {
            "h2_settings_order": "|h2so=", "h3_settings_order": "|h3so=",
            "h3_pseudo_header_order": "|h3ph=", "cert_compression_algos": "|cca=",
            "key_share_curves": "|ksc=", "alpn_protocols": "|alpn=",
            "alps_protocols": "|alps=", "pseudo_header_order": "|ph=",
            "supported_delegated_credentials_algorithms": "|sdca=",
            "supported_signature_algorithms": "|ssa=", "supported_versions": "|sv=",
        }
        for key, pfx in str_arrays.items():
            arr = ctc.get(key)
            if arr:
                h.update(pfx.encode("utf-8"))
                for i, s in enumerate(arr):
                    if i > 0:
                        h.update(b",")
                    h.update(str(s).encode("utf-8"))

        for skey, pfx in [("h2_settings", "|h2s:"), ("h3_settings", "|h3s:")]:
            settings = ctc.get(skey)
            if settings:
                for k in sorted(settings.keys()):
                    h.update(f"{pfx}{k}={settings[k]}".encode("utf-8"))

        ech_payloads = ctc.get("ech_candidate_payloads")
        if ech_payloads:
            for pld in ech_payloads:
                h.update(f"|echp:{pld}".encode("utf-8"))

        ech_suites = ctc.get("ech_candidate_cipher_suites")
        if ech_suites:
            for s in sorted(ech_suites, key=lambda x: (x.get("kdfId", ""), x.get("aeadId", ""))):
                h.update(f"|echcs:{s.get('kdfId', '')},{s.get('aeadId', '')}".encode("utf-8"))

        pri_frames = ctc.get("priority_frames")
        if pri_frames:
            for pf in pri_frames:
                pp = pf.get("priorityParam", {})
                h.update(
                    f"|pf:{pf.get('streamID', 0)},{pp.get('streamDep', 0)},"
                    f"{1 if pp.get('exclusive') else 0},{pp.get('weight', 0)}".encode("utf-8")
                )

        hp = ctc.get("header_priority")
        if hp:
            h.update(
                f"|hp:{hp.get('streamDep', 0)},{1 if hp.get('exclusive') else 0},"
                f"{hp.get('weight', 0)}".encode("utf-8")
            )

    return h.hexdigest()


# ---------------------------------------------------------------------------
# Shared RequestOptions builder — eliminates ~80 lines of duplicated
# C‑struct logic between Session.execute_request and AsyncSession._execute_async
# ---------------------------------------------------------------------------

def _populate_request_options(
    ffi: Any,
    opts: Any,
    keep_alive: list,
    defaults: Dict[str, Any],
    overrides: Dict[str, Any],
) -> None:
    """Set every field on *opts* by looking up ``overrides[name]`` first,
    then falling back to ``defaults[name]``.  Bool fields are auto‑converted
    to C ``int`` (0/1).  String / array / dict fields call the appropriate
    ``_build_*`` helper and extend *keep_alive*."""

    def _val(name: str, as_bool: bool = False) -> Any:
        v = overrides.get(name)
        if v is None:
            v = defaults.get(name)  # defensive: missing key → None instead of KeyError
        if as_bool:
            return 1 if v else 0
        return v

    # ---- String fields (nullable C strings) -------------------------------
    for field in (
        "proxy",
        "client_identifier",
        "server_name_overwrite",
        "request_host_override",
        "local_address",
    ):
        c_val = _c_string(ffi, _val(field))
        setattr(opts, field, c_val)
        if c_val != ffi.NULL:
            keep_alive.append(c_val)

    # ---- Array / dict fields (C arrays of structs) ------------------------
    (
        opts.pseudo_header_order,
        opts.pseudo_header_order_len,
    ) = _build_string_array(ffi, _val("pseudo_header_order"), keep_alive)

    (
        opts.h3_pseudo_header_order,
        opts.h3_pseudo_header_order_len,
    ) = _build_string_array(ffi, _val("h3_pseudo_header_order"), keep_alive)

    opts.default_headers, opts.default_headers_len = _build_headers(
        ffi, _val("default_headers"), keep_alive
    )
    opts.connect_headers, opts.connect_headers_len = _build_headers(
        ffi, _val("connect_headers"), keep_alive
    )
    (
        opts.certificate_pinning_hosts,
        opts.certificate_pinning_hosts_len,
    ) = _build_pin_entries(
        ffi, _val("certificate_pinning_hosts"), keep_alive
    )
    opts.request_cookies, opts.request_cookies_len = _build_headers(
        ffi, _val("request_cookies"), keep_alive
    )
    (
        opts.client_certificates,
        opts.client_certificates_len,
    ) = _build_client_certificates(
        ffi, _val("client_certificates"), keep_alive
    )
    opts.custom_tls_client = _build_custom_tls_client(
        ffi, _val("custom_tls_client"), keep_alive
    )

    # ---- Scalar fields (int / bool→int) -----------------------------------
    opts.timeout_seconds = _val("timeout_seconds")
    opts.timeout_milliseconds = _val("timeout_milliseconds")
    opts.follow_redirects = _val("follow_redirects", True)
    opts.insecure_skip_verify = _val("insecure_skip_verify", True)
    opts.force_http1 = _val("force_http1", True)
    opts.with_random_tls_extension_order = _val(
        "with_random_tls_extension_order", True
    )
    opts.with_protocol_racing = _val("with_protocol_racing", True)
    opts.with_default_bad_pin_handler = _val(
        "with_default_bad_pin_handler", True
    )
    opts.max_idle_connections = _val("max_idle_connections")
    opts.max_idle_connections_per_host = _val("max_idle_connections_per_host")
    opts.max_connections_per_host = _val("max_connections_per_host")
    opts.disable_keep_alives = _val("disable_keep_alives", True)
    opts.disable_compression = _val("disable_compression", True)
    opts.idle_conn_timeout_seconds = _val("idle_conn_timeout_seconds")
    opts.max_response_header_bytes = _val("max_response_header_bytes")
    opts.write_buffer_size = _val("write_buffer_size")
    opts.read_buffer_size = _val("read_buffer_size")
    opts.allow_empty_cookies = _val("allow_empty_cookies", True)
    opts.without_cookie_jar = _val("without_cookie_jar", True)
    opts.disable_http3 = _val("disable_http3", True)
    opts.disable_ipv4 = _val("disable_ipv4", True)
    opts.disable_ipv6 = _val("disable_ipv6", True)
    opts.catch_panics = _val("catch_panics", True)
    opts.with_debug = _val("with_debug", True)


# ---------------------------------------------------------------------------
# Response unpacking — shared between sync ExecuteRequest and async callback
# ---------------------------------------------------------------------------

def _unpack_c_response(ffi, raw_res) -> Response:
    """Unpack a C ResponseResult* into a Python Response object.

    Used by both the synchronous execute_request path and the async
    CFFI callback path.  Does NOT call FreeResponse — the caller is
    responsible for that.
    """
    status = raw_res.status_code
    blen = raw_res.body_len

    if blen > 0 and raw_res.body != ffi.NULL:
        body_bytes = ffi.buffer(raw_res.body, blen)[:]
    else:
        body_bytes = b""

    response_headers: Dict[str, List[str]] = {}
    rh_len = raw_res.response_headers_len
    if rh_len > 0 and raw_res.response_headers != ffi.NULL:
        for i in range(rh_len):
            h = raw_res.response_headers[i]
            if h.key != ffi.NULL and h.value != ffi.NULL:
                k = ffi.string(h.key).decode("utf-8", errors="replace")
                v = ffi.string(h.value).decode("utf-8", errors="replace")
                response_headers.setdefault(k, []).append(v)

    ct = ""
    for k, v in response_headers.items():
        if k.lower() == "content-type":
            ct = v[0] if v else ""
            break
    encoding = _charset_from_content_type(ct)
    try:
        text = body_bytes.decode(encoding)
    except (UnicodeDecodeError, LookupError):
        encoding = "utf-8"
        text = body_bytes.decode("utf-8", errors="replace")

    response_cookies: Dict[str, str] = {}
    ck_len = raw_res.cookies_len
    if ck_len > 0 and raw_res.cookies != ffi.NULL:
        for i in range(ck_len):
            ck_entry = raw_res.cookies[i]
            if ck_entry.key != ffi.NULL and ck_entry.value != ffi.NULL:
                cn = ffi.string(ck_entry.key).decode("utf-8", errors="replace")
                cv = ffi.string(ck_entry.value).decode("utf-8", errors="replace")
                response_cookies[cn] = cv

    target_url: Optional[str] = None
    if raw_res.target_url != ffi.NULL:
        target_url = ffi.string(raw_res.target_url).decode("utf-8", errors="replace")

    used_protocol: Optional[str] = None
    if raw_res.used_protocol != ffi.NULL:
        used_protocol = ffi.string(raw_res.used_protocol).decode("utf-8", errors="replace")

    return Response(
        status_code=status,
        headers=response_headers,
        content=body_bytes,
        text=text,
        encoding=encoding,
        url=target_url,
        cookies=response_cookies,
        used_protocol=used_protocol,
    )

# ---------------------------------------------------------------------------
# Synchronous Session
# ---------------------------------------------------------------------------

class Session:
    """同步 HTTP 客户端，封装 Go tls-client 引擎。

    Synchronous HTTP client wrapping the Go tls-client engine.
    """

    defaults: Dict[str, Any]

    # ------------------------------------------------------------------
    # Writable session properties — users can read/write after construction.
    # e.g.  session.headers = {"User-Agent": "..."}
    #       session.cookies = {"foo": "bar"}
    #       session.proxy = "http://127.0.0.1:8080"
    #       session.timeout = 10
    # ------------------------------------------------------------------

    # -- fingerprint / protocol --------------------------------------------

    @property
    def client_identifier(self) -> str:
        """TLS 指纹标识 / TLS fingerprint identifier."""
        return self.defaults["client_identifier"]

    @client_identifier.setter
    def client_identifier(self, value: str) -> None:
        self.defaults["client_identifier"] = value

    @property
    def force_http1(self) -> bool:
        """是否强制 HTTP/1.1 / Whether to force HTTP/1.1."""
        return bool(self.defaults["force_http1"])

    @force_http1.setter
    def force_http1(self, value: bool) -> None:
        self.defaults["force_http1"] = 1 if value else 0

    @property
    def disable_http3(self) -> bool:
        """是否完全禁用 HTTP/3 / Whether to disable HTTP/3."""
        return bool(self.defaults["disable_http3"])

    @disable_http3.setter
    def disable_http3(self, value: bool) -> None:
        self.defaults["disable_http3"] = 1 if value else 0

    @property
    def with_protocol_racing(self) -> bool:
        """是否启用协议竞速 / Whether to enable protocol racing."""
        return bool(self.defaults["with_protocol_racing"])

    @with_protocol_racing.setter
    def with_protocol_racing(self, value: bool) -> None:
        self.defaults["with_protocol_racing"] = 1 if value else 0

    @property
    def random_tls_extension_order(self) -> bool:
        """是否随机 TLS 扩展顺序 / Whether to randomise TLS extension order."""
        return bool(self.defaults["with_random_tls_extension_order"])

    @random_tls_extension_order.setter
    def random_tls_extension_order(self, value: bool) -> None:
        self.defaults["with_random_tls_extension_order"] = 1 if value else 0

    # -- timeout / redirect -------------------------------------------------

    @property
    def timeout(self) -> int:
        """请求超时时间（秒） / Request timeout in seconds."""
        return self.defaults["timeout_seconds"]

    @timeout.setter
    def timeout(self, value: int) -> None:
        self.defaults["timeout_seconds"] = value

    @property
    def timeout_milliseconds(self) -> int:
        """请求超时时间（毫秒） / Request timeout in milliseconds."""
        return self.defaults["timeout_milliseconds"]

    @timeout_milliseconds.setter
    def timeout_milliseconds(self, value: int) -> None:
        self.defaults["timeout_milliseconds"] = value

    @property
    def follow_redirects(self) -> bool:
        """是否跟随重定向 / Whether to follow redirects."""
        return bool(self.defaults["follow_redirects"])

    @follow_redirects.setter
    def follow_redirects(self, value: bool) -> None:
        self.defaults["follow_redirects"] = 1 if value else 0

    # -- TLS / certificate --------------------------------------------------

    @property
    def verify(self) -> bool:
        """是否验证 TLS 证书 / Whether to verify the TLS certificate."""
        return not bool(self.defaults["insecure_skip_verify"])

    @verify.setter
    def verify(self, value: bool) -> None:
        self.defaults["insecure_skip_verify"] = 0 if value else 1

    @property
    def server_name_overwrite(self) -> Optional[str]:
        """SNI 主机名覆盖 / SNI hostname override."""
        return self.defaults["server_name_overwrite"]

    @server_name_overwrite.setter
    def server_name_overwrite(self, value: Optional[str]) -> None:
        self.defaults["server_name_overwrite"] = value

    # -- proxy / local address ----------------------------------------------

    @property
    def proxy(self) -> Optional[str]:
        """代理 URL / Proxy URL."""
        return self.defaults["proxy"]

    @proxy.setter
    def proxy(self, value: Optional[str]) -> None:
        self.defaults["proxy"] = value

    @property
    def proxies(self) -> Optional[str]:
        """代理 URL（别名）/ Proxy URL (alias for :attr:`proxy`)."""
        return self.defaults["proxy"]

    @proxies.setter
    def proxies(self, value: Optional[str]) -> None:
        self.defaults["proxy"] = value

    @property
    def local_address(self) -> Optional[str]:
        """本地绑定地址 / Local bind address."""
        return self.defaults["local_address"]

    @local_address.setter
    def local_address(self, value: Optional[str]) -> None:
        self.defaults["local_address"] = value

    # -- header control -----------------------------------------------------

    @property
    def request_host_override(self) -> Optional[str]:
        """Host 请求头覆盖 / Host header override."""
        return self.defaults["request_host_override"]

    @request_host_override.setter
    def request_host_override(self, value: Optional[str]) -> None:
        self.defaults["request_host_override"] = value

    @property
    def pseudo_header_order(self) -> Optional[List[str]]:
        """HTTP/2 伪头顺序 / HTTP/2 pseudo-header order."""
        return self.defaults["pseudo_header_order"]

    @pseudo_header_order.setter
    def pseudo_header_order(self, value: Optional[List[str]]) -> None:
        self.defaults["pseudo_header_order"] = value

    @property
    def h3_pseudo_header_order(self) -> Optional[List[str]]:
        """HTTP/3 伪头顺序 / HTTP/3 pseudo-header order."""
        return self.defaults["h3_pseudo_header_order"]

    @h3_pseudo_header_order.setter
    def h3_pseudo_header_order(self, value: Optional[List[str]]) -> None:
        self.defaults["h3_pseudo_header_order"] = value

    @property
    def default_headers(self) -> Optional[Dict[str, str]]:
        """默认请求头字典 / Default headers dict."""
        return self.defaults["default_headers"]

    @default_headers.setter
    def default_headers(self, value: Optional[Dict[str, str]]) -> None:
        self.defaults["default_headers"] = value

    @property
    def headers(self) -> Optional[Dict[str, str]]:
        """默认请求头字典（别名）/ Default headers dict (alias for :attr:`default_headers`)."""
        return self.defaults["default_headers"]

    @headers.setter
    def headers(self, value: Optional[Dict[str, str]]) -> None:
        self.defaults["default_headers"] = value

    @property
    def connect_headers(self) -> Optional[Dict[str, str]]:
        """代理 CONNECT 隧道请求头字典 / Proxy CONNECT tunnel headers."""
        return self.defaults["connect_headers"]

    @connect_headers.setter
    def connect_headers(self, value: Optional[Dict[str, str]]) -> None:
        self.defaults["connect_headers"] = value

    # -- certificate pinning ------------------------------------------------

    @property
    def certificate_pinning_hosts(self) -> Optional[Dict[str, List[str]]]:
        """SSL 证书固定字典 / SSL certificate pinning dict."""
        return self.defaults["certificate_pinning_hosts"]

    @certificate_pinning_hosts.setter
    def certificate_pinning_hosts(self, value: Optional[Dict[str, List[str]]]) -> None:
        self.defaults["certificate_pinning_hosts"] = value

    @property
    def with_default_bad_pin_handler(self) -> bool:
        """是否调用默认 Bad-Pin 处理器 / Whether to invoke the default bad-pin handler."""
        return bool(self.defaults["with_default_bad_pin_handler"])

    @with_default_bad_pin_handler.setter
    def with_default_bad_pin_handler(self, value: bool) -> None:
        self.defaults["with_default_bad_pin_handler"] = 1 if value else 0

    # -- cookies -------------------------------------------------------------

    @property
    def request_cookies(self) -> Optional[Dict[str, str]]:
        """预置 Cookie 字典 / Pre-populated cookie dict."""
        return self.defaults["request_cookies"]

    @request_cookies.setter
    def request_cookies(self, value: Optional[Dict[str, str]]) -> None:
        self.defaults["request_cookies"] = value

    @property
    def cookies(self) -> Optional[Dict[str, str]]:
        """预置 Cookie 字典（别名）/ Pre-populated cookie dict (alias for :attr:`request_cookies`)."""
        return self.defaults["request_cookies"]

    @cookies.setter
    def cookies(self, value: Optional[Dict[str, str]]) -> None:
        self.defaults["request_cookies"] = value

    # -- custom TLS / client certs ------------------------------------------

    @property
    def custom_tls_client(self) -> Optional[Dict[str, Any]]:
        """完全自定义的 TLS 客户端配置 / Fully custom TLS client configuration."""
        return self.defaults["custom_tls_client"]

    @custom_tls_client.setter
    def custom_tls_client(self, value: Optional[Dict[str, Any]]) -> None:
        self.defaults["custom_tls_client"] = value

    @property
    def client_certificates(self) -> Optional[List[Dict[str, bytes]]]:
        """客户端证书列表 (mTLS) / Client certificates for mTLS."""
        return self.defaults["client_certificates"]

    @client_certificates.setter
    def client_certificates(self, value: Optional[List[Dict[str, bytes]]]) -> None:
        self.defaults["client_certificates"] = value

    # -- connection pool tuning ---------------------------------------------

    @property
    def max_idle_connections(self) -> int:
        """全局最大空闲连接数 / Global max idle connections."""
        return self.defaults["max_idle_connections"]

    @max_idle_connections.setter
    def max_idle_connections(self, value: int) -> None:
        self.defaults["max_idle_connections"] = value

    @property
    def max_idle_connections_per_host(self) -> int:
        """每 Host 最大空闲连接数 / Max idle connections per host."""
        return self.defaults["max_idle_connections_per_host"]

    @max_idle_connections_per_host.setter
    def max_idle_connections_per_host(self, value: int) -> None:
        self.defaults["max_idle_connections_per_host"] = value

    @property
    def max_connections_per_host(self) -> int:
        """每 Host 最大总连接数 / Max total connections per host."""
        return self.defaults["max_connections_per_host"]

    @max_connections_per_host.setter
    def max_connections_per_host(self, value: int) -> None:
        self.defaults["max_connections_per_host"] = value

    @property
    def disable_keep_alives(self) -> bool:
        """是否禁用 Keep-Alive / Whether to disable Keep-Alive."""
        return bool(self.defaults["disable_keep_alives"])

    @disable_keep_alives.setter
    def disable_keep_alives(self, value: bool) -> None:
        self.defaults["disable_keep_alives"] = 1 if value else 0

    @property
    def disable_compression(self) -> bool:
        """是否禁用响应解压 / Whether to disable decompression."""
        return bool(self.defaults["disable_compression"])

    @disable_compression.setter
    def disable_compression(self, value: bool) -> None:
        self.defaults["disable_compression"] = 1 if value else 0

    @property
    def idle_conn_timeout_seconds(self) -> int:
        """空闲连接超时（秒） / Idle connection timeout (seconds)."""
        return self.defaults["idle_conn_timeout_seconds"]

    @idle_conn_timeout_seconds.setter
    def idle_conn_timeout_seconds(self, value: int) -> None:
        self.defaults["idle_conn_timeout_seconds"] = value

    @property
    def max_response_header_bytes(self) -> int:
        """响应头最大字节数 / Max response header bytes."""
        return self.defaults["max_response_header_bytes"]

    @max_response_header_bytes.setter
    def max_response_header_bytes(self, value: int) -> None:
        self.defaults["max_response_header_bytes"] = value

    @property
    def write_buffer_size(self) -> int:
        """写缓冲区大小 / Write buffer size."""
        return self.defaults["write_buffer_size"]

    @write_buffer_size.setter
    def write_buffer_size(self, value: int) -> None:
        self.defaults["write_buffer_size"] = value

    @property
    def read_buffer_size(self) -> int:
        """读缓冲区大小 / Read buffer size."""
        return self.defaults["read_buffer_size"]

    @read_buffer_size.setter
    def read_buffer_size(self, value: int) -> None:
        self.defaults["read_buffer_size"] = value

    # -- IP stack / cookies / debug -----------------------------------------

    @property
    def disable_ipv4(self) -> bool:
        """是否禁用 IPv4 / Whether to disable IPv4."""
        return bool(self.defaults["disable_ipv4"])

    @disable_ipv4.setter
    def disable_ipv4(self, value: bool) -> None:
        self.defaults["disable_ipv4"] = 1 if value else 0

    @property
    def disable_ipv6(self) -> bool:
        """是否禁用 IPv6 / Whether to disable IPv6."""
        return bool(self.defaults["disable_ipv6"])

    @disable_ipv6.setter
    def disable_ipv6(self, value: bool) -> None:
        self.defaults["disable_ipv6"] = 1 if value else 0

    @property
    def allow_empty_cookies(self) -> bool:
        """是否允许空 Cookie / Whether to allow empty cookies."""
        return bool(self.defaults["allow_empty_cookies"])

    @allow_empty_cookies.setter
    def allow_empty_cookies(self, value: bool) -> None:
        self.defaults["allow_empty_cookies"] = 1 if value else 0

    @property
    def without_cookie_jar(self) -> bool:
        """是否禁用 Cookie Jar / Whether to disable Cookie Jar."""
        return bool(self.defaults["without_cookie_jar"])

    @without_cookie_jar.setter
    def without_cookie_jar(self, value: bool) -> None:
        self.defaults["without_cookie_jar"] = 1 if value else 0

    @property
    def catch_panics(self) -> bool:
        """是否捕获 Go panic / Whether to catch Go panics."""
        return bool(self.defaults["catch_panics"])

    @catch_panics.setter
    def catch_panics(self, value: bool) -> None:
        self.defaults["catch_panics"] = 1 if value else 0

    @property
    def with_debug(self) -> bool:
        """是否启用调试日志 / Whether to enable debug logging."""
        return bool(self.defaults["with_debug"])

    @with_debug.setter
    def with_debug(self, value: bool) -> None:
        self.defaults["with_debug"] = 1 if value else 0

    def __init__(
        self,
        *,
        # ── 指纹 / 协议 ──  /  Fingerprint / Protocol ──
        # TLS 指纹标识 / TLS fingerprint identifier
        client_identifier: ClientIdentifiers = "chrome_120",
        # 强制使用 HTTP/1.1 / Force HTTP/1.1
        force_http1: bool = False,
        # 完全禁用 HTTP/3（QUIC） / Completely disable HTTP/3 (QUIC)
        disable_http3: bool = False,
        # 启用协议竞速 / Enable protocol racing
        with_protocol_racing: bool = False,
        # 随机打乱 TLS 扩展的发送顺序 / Randomize TLS extension send order
        random_tls_extension_order: bool = True,
        # ── 超时 / 重定向 ──  /  Timeout / Redirect ──
        # 请求整体超时时间（秒） / Total request timeout in seconds
        timeout: int = 30,
        # 请求超时时间（毫秒） / Request timeout in milliseconds
        timeout_milliseconds: int = 0,
        # 是否自动跟随 HTTP 重定向 / Whether to automatically follow HTTP redirects
        follow_redirects: bool = False,
        # ── TLS / 证书 ──  /  TLS / Cert ──
        # 是否验证服务端 TLS 证书 / Whether to verify the server TLS certificate
        verify: bool = True,
        # 自定义 SNI / Custom SNI
        server_name_overwrite: Optional[str] = None,
        # ── 代理 ──  /  Proxy ──
        # 代理 URL / Proxy URL
        proxy: Optional[str] = None,
        # 绑定到指定的本地 IP 地址 / Bind to a specific local IP address
        local_address: Optional[str] = None,
        # ── 请求头控制 ──  /  Header Control ──
        # 覆盖 HTTP Host 请求头 / Override the HTTP Host header
        request_host_override: Optional[str] = None,
        # HTTP/2 伪头发送顺序 / HTTP/2 pseudo-header send order
        pseudo_header_order: Optional[List[str]] = None,
        # HTTP/3 伪头的发送顺序 / HTTP/3 pseudo-header send order
        h3_pseudo_header_order: Optional[List[str]] = None,
        # 默认请求头字典 / Default headers dict
        default_headers: Optional[Dict[str, str]] = None,
        # 代理 CONNECT 隧道请求头字典 / Proxy CONNECT tunnel headers dict
        connect_headers: Optional[Dict[str, str]] = None,
        # ── 证书固定 ──  /  Certificate Pinning ──
        # SSL 证书固定字典 / SSL certificate pinning dict
        certificate_pinning_hosts: Optional[Dict[str, List[str]]] = None,
        # 是否调用默认 Bad-Pin 处理器 / Whether to invoke the default bad-pin handler
        with_default_bad_pin_handler: bool = False,
        # ── Cookie ──
        # 预置 Cookie 字典 / Pre-populated cookie dict
        request_cookies: Optional[Dict[str, str]] = None,
        # ── 自定义 TLS ──  /  Custom TLS ──
        # 完全自定义的 TLS 客户端配置 (26 fields) / Fully custom TLS client configuration
        custom_tls_client: Optional[Dict[str, Any]] = None,
        # 客户端证书 (mTLS) / Client certificates for mTLS
        client_certificates: Optional[List[Dict[str, bytes]]] = None,
        # ── 连接池调优 ──  /  Connection Pool Tuning ──
        # 全局最大空闲连接数 / Global max idle connections
        max_idle_connections: int = 0,
        # 每个 Host 的最大空闲连接数 / Max idle connections per host
        max_idle_connections_per_host: int = 0,
        # 每个 Host 的最大总连接数 / Max total connections per host
        max_connections_per_host: int = 0,
        # 禁用 HTTP Keep-Alive / Disable HTTP Keep-Alive
        disable_keep_alives: bool = False,
        # 禁用响应体自动解压 / Disable automatic response body decompression
        disable_compression: bool = False,
        # 空闲连接的最大保持时间（秒） / Max idle time for keep-alive connections
        idle_conn_timeout_seconds: int = 0,
        # HTTP 响应头的最大字节数限制 / Max response header bytes limit
        max_response_header_bytes: int = 0,
        # Socket 写缓冲区大小（字节） / Socket write buffer size (bytes)
        write_buffer_size: int = 0,
        # Socket 读缓冲区大小（字节） / Socket read buffer size (bytes)
        read_buffer_size: int = 0,
        # ── IP 协议栈控制 ──  /  IP Stack Control ──
        # 禁用 IPv4 / Disable IPv4
        disable_ipv4: bool = False,
        # 禁用 IPv6 / Disable IPv6
        disable_ipv6: bool = False,
        # ── Cookie ──
        # 是否允许空 Cookie / Whether to allow empty-value cookies
        allow_empty_cookies: bool = False,
        # 完全禁用 Cookie Jar / Completely disable Cookie Jar
        without_cookie_jar: bool = False,
        # ── 调试 / 安全 ──  /  Debug / Safety ──
        # 是否在 Go 侧捕获 panic / Whether to catch Go panics
        catch_panics: bool = True,
        # 启用调试日志输出 / Enable debug log output
        with_debug: bool = False,
    ) -> None:
        self.defaults = {
            "client_identifier": client_identifier,
            "timeout_seconds": timeout,
            "timeout_milliseconds": timeout_milliseconds,
            "follow_redirects": 1 if follow_redirects else 0,
            "insecure_skip_verify": 0 if verify else 1,
            "force_http1": 1 if force_http1 else 0,
            "with_random_tls_extension_order": (
                1 if random_tls_extension_order else 0
            ),
            "with_protocol_racing": 1 if with_protocol_racing else 0,
            "server_name_overwrite": server_name_overwrite,
            "request_host_override": request_host_override,
            "local_address": local_address,
            "proxy": proxy,
            "pseudo_header_order": pseudo_header_order,
            "h3_pseudo_header_order": h3_pseudo_header_order,
            "default_headers": (
                default_headers
                if default_headers is not None
                else DEFAULT_HEADERS.get(client_identifier)
            ),
            "connect_headers": connect_headers,
            "certificate_pinning_hosts": certificate_pinning_hosts,
            "with_default_bad_pin_handler": (
                1 if with_default_bad_pin_handler else 0
            ),
            "request_cookies": request_cookies,
            "custom_tls_client": custom_tls_client,
            "client_certificates": client_certificates,
            "max_idle_connections": max_idle_connections,
            "max_idle_connections_per_host": max_idle_connections_per_host,
            "max_connections_per_host": max_connections_per_host,
            "disable_keep_alives": 1 if disable_keep_alives else 0,
            "disable_compression": 1 if disable_compression else 0,
            "idle_conn_timeout_seconds": idle_conn_timeout_seconds,
            "max_response_header_bytes": max_response_header_bytes,
            "write_buffer_size": write_buffer_size,
            "read_buffer_size": read_buffer_size,
            "allow_empty_cookies": 1 if allow_empty_cookies else 0,
            "without_cookie_jar": 1 if without_cookie_jar else 0,
            "disable_http3": 1 if disable_http3 else 0,
            "disable_ipv4": 1 if disable_ipv4 else 0,
            "disable_ipv6": 1 if disable_ipv6 else 0,
            "catch_panics": 1 if catch_panics else 0,
            "with_debug": 1 if with_debug else 0,
        }

    def stream_to_file(
        self,
        # HTTP 方法 / HTTP method
        method: str,
        # 请求 URL / Request URL
        url: str,
        # 输出文件路径 / Output file path
        output_path: str,
        *,
        # 请求头字典 / Request headers dict
        headers: Optional[Dict[str, str]] = None,
        # 请求头发送顺序 / Header send order
        header_order: Optional[List[str]] = None,
        # 请求体原始字节串 / Request body as raw bytes
        body: Optional[bytes] = None,
        # 块大小（字节） / Chunk size per read (bytes)
        chunk_size: int = 8192,
        # 可选的 EOF 标记字符串 / Optional EOF marker string
        eof_marker: Optional[str] = None,
        **kwargs: Any,
    ) -> Response:
        """执行请求并将响应体流式写入磁盘。

        Execute a request and stream the response body to disk.
        """

        ffi, _ = _get_ffi()

        keep_alive: list = []
        c_path = _c_string(ffi, output_path)
        keep_alive.append(c_path)

        c_eof = _c_string(ffi, eof_marker)
        if c_eof != ffi.NULL:
            keep_alive.append(c_eof)

        return self.execute_request(
            method,
            url,
            headers=headers,
            header_order=header_order,
            body=body,
            _stream_output_path=c_path,
            _stream_output_block_size=chunk_size,
            _stream_output_eof_symbol=c_eof,
            _stream_keep_alive=keep_alive,
            **kwargs,
        )

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *args: Any) -> None:
        pass

    def execute_request(
        self,
        # HTTP 方法 / HTTP method
        method: str,
        # 完整的请求 URL / Full request URL including scheme and hostname
        url: str,
        *,
        # 请求头字典 / Request headers dict
        headers: Optional[Dict[str, str]] = None,
        # 请求头的发送顺序列表 / Header send-order list
        header_order: Optional[List[str]] = None,
        # 请求体原始字节串 / Request body as raw bytes
        body: Optional[bytes] = None,
        # ── 每请求覆盖参数 / Per-request overrides ──
        # 覆盖 TLS 指纹标识 / Override TLS fingerprint identifier
        client_identifier: Optional[str] = None,
        # 覆盖超时时间（秒） / Override timeout (seconds)
        timeout: Optional[int] = None,
        # 覆盖超时时间（毫秒） / Override timeout (milliseconds)
        timeout_milliseconds: Optional[int] = None,
        # 覆盖重定向跟随策略 / Override redirect-following policy
        follow_redirects: Optional[bool] = None,
        # 覆盖 TLS 证书校验 / Override TLS certificate verification
        verify: Optional[bool] = None,
        # 覆盖 HTTP/1.1 强制开关 / Override force HTTP/1.1
        force_http1: Optional[bool] = None,
        # 覆盖 TLS 扩展随机化 / Override TLS extension randomisation
        random_tls_extension_order: Optional[bool] = None,
        # 覆盖协议竞速开关 / Override protocol racing
        with_protocol_racing: Optional[bool] = None,
        # 覆盖 SNI 主机名 / Override SNI hostname
        server_name_overwrite: Optional[str] = None,
        # 覆盖 HTTP Host 请求头 / Override HTTP Host header
        request_host_override: Optional[str] = None,
        # 覆盖代理 URL / Override proxy URL
        proxy: Optional[str] = None,
        # 覆盖本地绑定地址 / Override local bind address
        local_address: Optional[str] = None,
        # 覆盖 HTTP/2 伪头顺序 / Override HTTP/2 pseudo-header order
        pseudo_header_order: Optional[List[str]] = None,
        # 覆盖 HTTP/3 伪头顺序 / Override HTTP/3 pseudo-header order
        h3_pseudo_header_order: Optional[List[str]] = None,
        # 覆盖默认请求头字典 / Override default headers dict
        default_headers: Optional[Dict[str, str]] = None,
        # 覆盖代理 CONNECT 隧道请求头 / Override proxy CONNECT tunnel headers
        connect_headers: Optional[Dict[str, str]] = None,
        # 覆盖 SSL 证书固定字典 / Override SSL certificate pinning dict
        certificate_pinning_hosts: Optional[Dict[str, List[str]]] = None,
        # 覆盖 Bad-Pin 处理器开关 / Override default bad-pin handler toggle
        with_default_bad_pin_handler: Optional[bool] = None,
        # 覆盖预置 Cookie 字典 / Override pre-populated cookie dict
        request_cookies: Optional[Dict[str, str]] = None,
        # 覆盖客户端证书列表 / Override client certificate list
        client_certificates: Optional[List[Dict[str, bytes]]] = None,
        # 覆盖自定义 TLS 客户端配置 / Override custom TLS client configuration
        custom_tls_client: Optional[Dict[str, Any]] = None,
        # 覆盖全局最大空闲连接数 / Override global max idle connections
        max_idle_connections: Optional[int] = None,
        # 覆盖每 Host 最大空闲连接数 / Override max idle connections per host
        max_idle_connections_per_host: Optional[int] = None,
        # 覆盖每 Host 最大总连接数 / Override max total connections per host
        max_connections_per_host: Optional[int] = None,
        # 覆盖 Keep-Alive 禁用 / Override disable Keep-Alive
        disable_keep_alives: Optional[bool] = None,
        # 覆盖压缩禁用 / Override disable compression
        disable_compression: Optional[bool] = None,
        # 覆盖空闲连接超时 / Override idle connection timeout
        idle_conn_timeout_seconds: Optional[int] = None,
        # 覆盖响应头最大字节数 / Override max response header bytes
        max_response_header_bytes: Optional[int] = None,
        # 覆盖写缓冲区大小 / Override write buffer size
        write_buffer_size: Optional[int] = None,
        # 覆盖读缓冲区大小 / Override read buffer size
        read_buffer_size: Optional[int] = None,
        # 覆盖空 Cookie 允许 / Override allow-empty-cookies
        allow_empty_cookies: Optional[bool] = None,
        # 覆盖禁用 Cookie Jar / Override disable Cookie Jar
        without_cookie_jar: Optional[bool] = None,
        # 覆盖 HTTP/3 禁用 / Override disable HTTP/3
        disable_http3: Optional[bool] = None,
        # 覆盖 IPv4 禁用 / Override disable IPv4
        disable_ipv4: Optional[bool] = None,
        # 覆盖 IPv6 禁用 / Override disable IPv6
        disable_ipv6: Optional[bool] = None,
        # 覆盖 panic 捕获 / Override catch-panics
        catch_panics: Optional[bool] = None,
        # 覆盖调试日志 / Override debug logging
        with_debug: Optional[bool] = None,
        **kwargs: Any,
    ) -> Response:
        """通过 Go 引擎执行单次 HTTP 请求。

        Execute a single HTTP request through the Go engine.
        """
        ffi, lib = _get_ffi()

        def _val(name: str, override, as_bool: bool = False):
            v = override if override is not None else self.defaults.get(name)
            if as_bool:
                return 1 if v else 0
            return v

        keep_alive: list = []

        # ---- build C HttpHeader array -------------------------------------
        hdr_ptr, hdr_len = _build_headers(ffi, headers, keep_alive)

        # ---- build header_order array -------------------------------------
        ho_ptr, ho_len = _build_string_array(ffi, header_order, keep_alive)

        # ---- build pseudo_header_order array ------------------------------
        ph_ptr, ph_len = _build_string_array(
            ffi, _val("pseudo_header_order", pseudo_header_order), keep_alive
        )

        # ---- build h3_pseudo_header_order array ---------------------------
        h3ph_ptr, h3ph_len = _build_string_array(
            ffi, _val("h3_pseudo_header_order", h3_pseudo_header_order), keep_alive
        )

        # ---- build default_headers array ----------------------------------
        dh_ptr, dh_len = _build_headers(
            ffi, _val("default_headers", default_headers), keep_alive
        )

        # ---- build connect_headers array ----------------------------------
        ch_ptr, ch_len = _build_headers(
            ffi, _val("connect_headers", connect_headers), keep_alive
        )

        # ---- build certificate_pinning_hosts array -------------------------
        cp_ptr, cp_len = _build_pin_entries(
            ffi, _val("certificate_pinning_hosts", certificate_pinning_hosts), keep_alive
        )

        # ---- build request_cookies array -----------------------------------
        rc_ptr, rc_len = _build_headers(
            ffi, _val("request_cookies", request_cookies), keep_alive
        )

        # ---- build client_certificates array --------------------------------
        cc_ptr, cc_len = _build_client_certificates(
            ffi, _val("client_certificates", client_certificates), keep_alive
        )

        # ---- build custom_tls_client --------------------------------------
        ctc_ptr = _build_custom_tls_client(
            ffi, _val("custom_tls_client", custom_tls_client), keep_alive
        )

        # ---- pre-compute cache key hash (avoids ~50 CGO calls on cache hit) --------
        # Resolve insecure_skip_verify considering the verify override
        if verify is not None:
            _isv = 0 if verify else 1
        else:
            _isv = _val("insecure_skip_verify", None, True)
        ck_hash = _compute_cache_key_hash({
            "client_identifier": _val("client_identifier", client_identifier) or "",
            "proxy": _val("proxy", proxy) or "",
            "server_name_overwrite": _val("server_name_overwrite", server_name_overwrite) or "",
            "local_address": _val("local_address", local_address) or "",
            "insecure_skip_verify": _isv,
            "force_http1": _val("force_http1", force_http1, True),
            "with_random_tls_extension_order": _val("with_random_tls_extension_order", random_tls_extension_order, True),
            "with_protocol_racing": _val("with_protocol_racing", with_protocol_racing, True),
            "max_idle_connections": _val("max_idle_connections", max_idle_connections),
            "max_idle_connections_per_host": _val("max_idle_connections_per_host", max_idle_connections_per_host),
            "max_connections_per_host": _val("max_connections_per_host", max_connections_per_host),
            "max_response_header_bytes": _val("max_response_header_bytes", max_response_header_bytes),
            "write_buffer_size": _val("write_buffer_size", write_buffer_size),
            "read_buffer_size": _val("read_buffer_size", read_buffer_size),
            "idle_conn_timeout_seconds": _val("idle_conn_timeout_seconds", idle_conn_timeout_seconds),
            "disable_keep_alives": _val("disable_keep_alives", disable_keep_alives, True),
            "disable_compression": _val("disable_compression", disable_compression, True),
            "disable_http3": _val("disable_http3", disable_http3, True),
            "disable_ipv4": _val("disable_ipv4", disable_ipv4, True),
            "disable_ipv6": _val("disable_ipv6", disable_ipv6, True),
            "follow_redirects": _val("follow_redirects", follow_redirects, True),
            "without_cookie_jar": _val("without_cookie_jar", without_cookie_jar, True),
            "allow_empty_cookies": _val("allow_empty_cookies", allow_empty_cookies, True),
            "with_default_bad_pin_handler": _val("with_default_bad_pin_handler", with_default_bad_pin_handler, True),
            "timeout_seconds": _val("timeout_seconds", timeout),
            "timeout_milliseconds": _val("timeout_milliseconds", timeout_milliseconds),
            "pseudo_header_order": _val("pseudo_header_order", pseudo_header_order),
            "h3_pseudo_header_order": _val("h3_pseudo_header_order", h3_pseudo_header_order),
            "default_headers": _val("default_headers", default_headers),
            "connect_headers": _val("connect_headers", connect_headers),
            "certificate_pinning_hosts": _val("certificate_pinning_hosts", certificate_pinning_hosts),
            "client_certificates": _val("client_certificates", client_certificates),
            "custom_tls_client": _val("custom_tls_client", custom_tls_client),
        })
        c_ck = _c_string(ffi, ck_hash)
        if c_ck != ffi.NULL:
            keep_alive.append(c_ck)

        # ---- build body (zero-copy) ---------------------------------------
        # ffi.from_buffer returns a pointer into Python's bytes buffer without
        # copying.  keep_alive anchors the pointer so Python does not GC the
        # buffer while Go reads from it (sync: blocked; async: _pending_requests).
        if body is not None:
            body_ptr = ffi.from_buffer(body)
            keep_alive.append(body_ptr)
            body_len = len(body)
        else:
            body_ptr = ffi.NULL
            body_len = 0

        # ---- build RequestOptions -----------------------------------------
        opts = ffi.new("RequestOptions *")
        keep_alive.append(opts)

        c_method = ffi.new("char[]", method.encode("utf-8"))
        c_url = ffi.new("char[]", url.encode("utf-8"))
        keep_alive.extend([c_method, c_url])

        opts.method = c_method
        opts.url = c_url
        opts.body = body_ptr
        opts.body_len = body_len

        c_proxy = _c_string(ffi, _val("proxy", proxy))
        c_ci = _c_string(ffi, _val("client_identifier", client_identifier))
        c_sni = _c_string(ffi, _val("server_name_overwrite", server_name_overwrite))
        c_host_override = _c_string(ffi, _val("request_host_override", request_host_override))
        c_local_addr = _c_string(ffi, _val("local_address", local_address))
        for c in (c_proxy, c_ci, c_sni, c_host_override, c_local_addr):
            if c != ffi.NULL:
                keep_alive.append(c)

        opts.proxy = c_proxy
        opts.client_identifier = c_ci
        opts.headers = hdr_ptr
        opts.headers_len = hdr_len
        opts.header_order = ho_ptr
        opts.header_order_len = ho_len
        opts.pseudo_header_order = ph_ptr
        opts.pseudo_header_order_len = ph_len
        opts.h3_pseudo_header_order = h3ph_ptr
        opts.h3_pseudo_header_order_len = h3ph_len
        opts.default_headers = dh_ptr
        opts.default_headers_len = dh_len
        opts.connect_headers = ch_ptr
        opts.connect_headers_len = ch_len
        opts.certificate_pinning_hosts = cp_ptr
        opts.certificate_pinning_hosts_len = cp_len
        opts.with_default_bad_pin_handler = _val(
            "with_default_bad_pin_handler", with_default_bad_pin_handler, True
        )
        opts.request_cookies = rc_ptr
        opts.request_cookies_len = rc_len
        opts.client_certificates = cc_ptr
        opts.client_certificates_len = cc_len
        opts.custom_tls_client = ctc_ptr
        opts.cache_key_hash = c_ck

        opts.timeout_seconds = _val("timeout_seconds", timeout)
        opts.timeout_milliseconds = _val("timeout_milliseconds", timeout_milliseconds)
        opts.follow_redirects = _val("follow_redirects", follow_redirects, True)
        if verify is not None:
            opts.insecure_skip_verify = 0 if verify else 1
        else:
            opts.insecure_skip_verify = self.defaults["insecure_skip_verify"]
        opts.force_http1 = _val("force_http1", force_http1, True)
        opts.with_random_tls_extension_order = _val(
            "with_random_tls_extension_order", random_tls_extension_order, True
        )
        opts.with_protocol_racing = _val(
            "with_protocol_racing", with_protocol_racing, True
        )
        opts.server_name_overwrite = c_sni
        opts.request_host_override = c_host_override
        opts.local_address = c_local_addr
        opts.max_idle_connections = _val("max_idle_connections", max_idle_connections)
        opts.max_idle_connections_per_host = _val(
            "max_idle_connections_per_host", max_idle_connections_per_host
        )
        opts.max_connections_per_host = _val(
            "max_connections_per_host", max_connections_per_host
        )
        opts.disable_keep_alives = _val("disable_keep_alives", disable_keep_alives, True)
        opts.disable_compression = _val("disable_compression", disable_compression, True)
        opts.idle_conn_timeout_seconds = _val(
            "idle_conn_timeout_seconds", idle_conn_timeout_seconds
        )
        opts.max_response_header_bytes = _val(
            "max_response_header_bytes", max_response_header_bytes
        )
        opts.write_buffer_size = _val("write_buffer_size", write_buffer_size)
        opts.read_buffer_size = _val("read_buffer_size", read_buffer_size)
        opts.allow_empty_cookies = _val("allow_empty_cookies", allow_empty_cookies, True)
        opts.without_cookie_jar = _val("without_cookie_jar", without_cookie_jar, True)
        opts.disable_http3 = _val("disable_http3", disable_http3, True)
        opts.disable_ipv4 = _val("disable_ipv4", disable_ipv4, True)
        opts.disable_ipv6 = _val("disable_ipv6", disable_ipv6, True)
        opts.catch_panics = _val("catch_panics", catch_panics, True)
        opts.with_debug = _val("with_debug", with_debug, True)

        # ---- streaming fields (injected by stream_to_file) -----------------
        stream_path = kwargs.pop("_stream_output_path", ffi.NULL)
        stream_bs = kwargs.pop("_stream_output_block_size", 0)
        stream_eof = kwargs.pop("_stream_output_eof_symbol", ffi.NULL)
        stream_keep = kwargs.pop("_stream_keep_alive", None)
        if stream_keep is not None:
            keep_alive.extend(stream_keep)
        opts.stream_output_path = stream_path
        opts.stream_output_block_size = stream_bs
        opts.stream_output_eof_symbol = stream_eof

        # ---- call Go ------------------------------------------------------
        raw_res = lib.ExecuteRequest(opts)

        if raw_res == ffi.NULL:
            raise RuntimeError("Go engine returned NULL – likely memory allocation failure")

        raw_res = ffi.gc(raw_res, lib.FreeResponse)

        if raw_res.err_msg != ffi.NULL:
            err = ffi.string(raw_res.err_msg).decode("utf-8", errors="replace")
            raise RuntimeError(err)

        return _unpack_c_response(ffi, raw_res)

    def typed_request(self, req: Request) -> Response:
        """使用 :class:`Request` 强类型对象执行 HTTP 请求。

        Execute an HTTP request using a :class:`Request` strongly-typed object.
        """
        method = req["method"]
        url = req["url"]
        kwargs = {k: v for k, v in req.items() if k not in ("method", "url")}
        return self.execute_request(method, url, **kwargs)

    def get(self, url: str, *, headers: Optional[Dict[str, str]] = None, **kwargs: Any) -> Response:
        return self.execute_request("GET", url, headers=headers, **kwargs)

    def post(self, url: str, *, headers: Optional[Dict[str, str]] = None, body: Optional[bytes] = None, **kwargs: Any) -> Response:
        return self.execute_request("POST", url, headers=headers, body=body, **kwargs)

    def head(self, url: str, *, headers: Optional[Dict[str, str]] = None, **kwargs: Any) -> Response:
        return self.execute_request("HEAD", url, headers=headers, **kwargs)

    def put(self, url: str, *, headers: Optional[Dict[str, str]] = None, body: Optional[bytes] = None, **kwargs: Any) -> Response:
        return self.execute_request("PUT", url, headers=headers, body=body, **kwargs)

    def delete(self, url: str, *, headers: Optional[Dict[str, str]] = None, **kwargs: Any) -> Response:
        return self.execute_request("DELETE", url, headers=headers, **kwargs)

    def patch(self, url: str, *, headers: Optional[Dict[str, str]] = None, body: Optional[bytes] = None, **kwargs: Any) -> Response:
        return self.execute_request("PATCH", url, headers=headers, body=body, **kwargs)

    @staticmethod
    def clear_client_pool() -> None:
        """Close all idle connections in the global Go client pool."""
        _, lib = _get_ffi()
        lib.ClearClientPool()

    @staticmethod
    def set_pool_ttl(seconds: int) -> None:
        """Set the TTL for cached HttpClient entries (default 300 s = 5 min).

        Entries not accessed within this duration are evicted by the
        background scanner.  Set to a large value to keep clients longer;
        set lower for memory-constrained environments.
        """
        _, lib = _get_ffi()
        lib.SetPoolTTL(seconds)

    @staticmethod
    def set_pool_scan_interval(seconds: int) -> None:
        """Set the interval for the background eviction scanner (default 60 s).

        Shorter intervals catch stale entries sooner but consume more CPU.
        """
        _, lib = _get_ffi()
        lib.SetPoolScanInterval(seconds)


# ---------------------------------------------------------------------------
# Async callback bridge — Go goroutine → Python CFFI callback → asyncio Future
# ---------------------------------------------------------------------------

# Registry of pending async requests.
# request_id → (future, keep_alive, timeout_handle)
#   future         — asyncio.Future resolved by the CFFI callback
#   keep_alive     — list of CFFI pointers that must outlive the Go goroutine
#   timeout_handle — asyncio.Handle; cancelled when callback fires, fires a
#                     defensive cleanup if the Go goroutine never responds
_pending_requests: Dict[int, tuple] = {}
_pending_lock = threading.Lock()
_request_counter = 0


def _next_request_id() -> int:
    global _request_counter
    _request_counter += 1
    return _request_counter


def _make_async_callback(ffi, lib):
    """Create a CFFI callback that Go goroutines invoke with results.

    The callback is called from a Go-managed OS thread (not the Python main
    thread).  CFFI internally calls PyGILState_Ensure to safely acquire the
    GIL before entering Python code.

    Lifecycle (per the 9-step user blueprint):
    1. Python calls RequestAsync → Go deep-copies → returns immediately
    2. Go goroutine executes HTTP request
    3. Go allocates CResponseResult on C heap via C.malloc
    4. Go calls this callback with (request_id, CResponseResult*)
    5. Python unpacks CResponseResult → Response object
    6. Python calls FreeResponse to release C memory
    7. Python uses loop.call_soon_threadsafe to resolve the Future
    """

    @ffi.callback("void(uintptr_t, ResponseResult*)")
    def _on_async_response(request_id: int, raw_res: Any) -> None:
        # The ENTIRE callback body MUST be wrapped in try/except Exception.
        # This callback executes on a Go-managed OS thread.  If any Python
        # exception escapes uncaught, the Python interpreter crashes with
        # Fatal Python error: Segmentation fault (Constraint 3).
        try:
            # Step 5-6: Unpack response
            if raw_res == ffi.NULL or raw_res.err_msg != ffi.NULL:
                err = "Go engine returned NULL"
                if raw_res != ffi.NULL and raw_res.err_msg != ffi.NULL:
                    err = ffi.string(raw_res.err_msg).decode("utf-8", errors="replace")
                response: Any = RuntimeError(err)
            else:
                response = _unpack_c_response(ffi, raw_res)
        except Exception as exc:
            response = exc
        finally:
            # Step 6: Free C memory in all code paths (success, error, panic)
            if raw_res != ffi.NULL:
                lib.FreeResponse(raw_res)

        # Step 9: Schedule Future resolution on the event loop thread.
        # Must use call_soon_threadsafe — direct set_result/set_exception
        # from a non-event-loop thread is NOT thread-safe (Constraint 4).
        try:
            with _pending_lock:
                future, _keep_alive, timeout_handle = _pending_requests.pop(
                    request_id, (None, None, None)
                )
                # _keep_alive is now released — the goroutine has finished,
                # so the C pointers it held via unsafe.Slice are no longer needed.

            # Cancel the defensive timeout — the Go goroutine completed.
            if timeout_handle is not None:
                timeout_handle.cancel()

            if future is None:
                return  # request was cancelled or timed out

            if not future.done():
                loop = future.get_loop()
                if isinstance(response, Exception):
                    loop.call_soon_threadsafe(future.set_exception, response)
                else:
                    loop.call_soon_threadsafe(future.set_result, response)
        except Exception:
            # If even Future resolution fails, there is nothing we can do —
            # the event loop may be shut down.  Silently swallow to prevent
            # a process crash.
            pass

    return _on_async_response


# Lazy-initialised callback — must be created after ffi is loaded and kept alive.
# Protected by a lock to prevent race conditions when multiple AsyncSession
# instances are created concurrently from different threads.
_async_callback = None
_async_callback_lock = threading.Lock()


def _get_async_callback(ffi, lib):
    """Return the singleton CFFI callback, creating it once under lock.

    Always acquires _async_callback_lock — double‑checked locking is unsafe
    under free‑threaded Python (PEP 703) because _async_callback may be
    partially visible without a synchronisation edge.  Contention is
    negligible: the callback is created once and cached thereafter.
    """
    global _async_callback
    with _async_callback_lock:
        if _async_callback is None:
            _async_callback = _make_async_callback(ffi, lib)
        return _async_callback


class AsyncSession:
    """True async HTTP client — no thread pool, no blocking.

    Uses Go goroutines + CFFI callbacks + asyncio Future:
    - Python calls RequestAsync (returns instantly after Go deep-copies)
    - Go goroutine executes HTTP I/O in the background
    - Go invokes CFFI callback when done
    - Python resolves asyncio.Future via call_soon_threadsafe

    Compatible with uvloop / winloop for maximum event-loop performance.
    """

    def __init__(
        self,
        *,
        # ── 指纹 / 协议 ──  /  Fingerprint / Protocol ──
        # TLS 指纹标识 / TLS fingerprint identifier
        client_identifier: ClientIdentifiers = "chrome_120",
        # 强制使用 HTTP/1.1 / Force HTTP/1.1
        force_http1: bool = False,
        # 完全禁用 HTTP/3（QUIC） / Completely disable HTTP/3 (QUIC)
        disable_http3: bool = False,
        # 启用协议竞速 / Enable protocol racing
        with_protocol_racing: bool = False,
        # 随机打乱 TLS 扩展的发送顺序 / Randomize TLS extension send order
        random_tls_extension_order: bool = True,
        # ── 超时 / 重定向 ──  /  Timeout / Redirect ──
        # 请求整体超时时间（秒） / Total request timeout in seconds
        timeout: int = 30,
        # 请求超时时间（毫秒） / Request timeout in milliseconds
        timeout_milliseconds: int = 0,
        # 是否自动跟随 HTTP 重定向 / Whether to automatically follow HTTP redirects
        follow_redirects: bool = False,
        # ── TLS / 证书 ──  /  TLS / Cert ──
        # 是否验证服务端 TLS 证书 / Whether to verify the server TLS certificate
        verify: bool = True,
        # 自定义 SNI / Custom SNI
        server_name_overwrite: Optional[str] = None,
        # ── 代理 ──  /  Proxy ──
        # 代理 URL / Proxy URL
        proxy: Optional[str] = None,
        # 绑定到指定的本地 IP 地址 / Bind to a specific local IP address
        local_address: Optional[str] = None,
        # ── 请求头控制 ──  /  Header Control ──
        # 覆盖 HTTP Host 请求头 / Override the HTTP Host header
        request_host_override: Optional[str] = None,
        # HTTP/2 伪头发送顺序 / HTTP/2 pseudo-header send order
        pseudo_header_order: Optional[List[str]] = None,
        # HTTP/3 伪头的发送顺序 / HTTP/3 pseudo-header send order
        h3_pseudo_header_order: Optional[List[str]] = None,
        # 默认请求头字典 / Default headers dict
        default_headers: Optional[Dict[str, str]] = None,
        # 代理 CONNECT 隧道请求头字典 / Proxy CONNECT tunnel headers dict
        connect_headers: Optional[Dict[str, str]] = None,
        # ── 证书固定 ──  /  Certificate Pinning ──
        # SSL 证书固定字典 / SSL certificate pinning dict
        certificate_pinning_hosts: Optional[Dict[str, List[str]]] = None,
        # 是否调用默认 Bad-Pin 处理器 / Whether to invoke the default bad-pin handler
        with_default_bad_pin_handler: bool = False,
        # ── Cookie ──
        # 预置 Cookie 字典 / Pre-populated cookie dict
        request_cookies: Optional[Dict[str, str]] = None,
        # ── 自定义 TLS ──  /  Custom TLS ──
        # 完全自定义的 TLS 客户端配置 (26 fields) / Fully custom TLS client configuration
        custom_tls_client: Optional[Dict[str, Any]] = None,
        # 客户端证书 (mTLS) / Client certificates for mTLS
        client_certificates: Optional[List[Dict[str, bytes]]] = None,
        # ── 连接池调优 ──  /  Connection Pool Tuning ──
        # 全局最大空闲连接数 / Global max idle connections
        max_idle_connections: int = 0,
        # 每个 Host 的最大空闲连接数 / Max idle connections per host
        max_idle_connections_per_host: int = 0,
        # 每个 Host 的最大总连接数 / Max total connections per host
        max_connections_per_host: int = 0,
        # 禁用 HTTP Keep-Alive / Disable HTTP Keep-Alive
        disable_keep_alives: bool = False,
        # 禁用响应体自动解压 / Disable automatic response body decompression
        disable_compression: bool = False,
        # 空闲连接的最大保持时间（秒） / Max idle time for keep-alive connections
        idle_conn_timeout_seconds: int = 0,
        # HTTP 响应头的最大字节数限制 / Max response header bytes limit
        max_response_header_bytes: int = 0,
        # Socket 写缓冲区大小（字节） / Socket write buffer size (bytes)
        write_buffer_size: int = 0,
        # Socket 读缓冲区大小（字节） / Socket read buffer size (bytes)
        read_buffer_size: int = 0,
        # ── IP 协议栈控制 ──  /  IP Stack Control ──
        # 禁用 IPv4 / Disable IPv4
        disable_ipv4: bool = False,
        # 禁用 IPv6 / Disable IPv6
        disable_ipv6: bool = False,
        # ── Cookie ──
        # 是否允许空 Cookie / Whether to allow empty-value cookies
        allow_empty_cookies: bool = False,
        # 完全禁用 Cookie Jar / Completely disable Cookie Jar
        without_cookie_jar: bool = False,
        # ── 调试 / 安全 ──  /  Debug / Safety ──
        # 是否在 Go 侧捕获 panic / Whether to catch Go panics
        catch_panics: bool = True,
        # 启用调试日志输出 / Enable debug log output
        with_debug: bool = False,
    ) -> None:
        self._session = Session(
            client_identifier=client_identifier,
            force_http1=force_http1,
            disable_http3=disable_http3,
            with_protocol_racing=with_protocol_racing,
            random_tls_extension_order=random_tls_extension_order,
            timeout=timeout,
            timeout_milliseconds=timeout_milliseconds,
            follow_redirects=follow_redirects,
            verify=verify,
            server_name_overwrite=server_name_overwrite,
            proxy=proxy,
            local_address=local_address,
            request_host_override=request_host_override,
            pseudo_header_order=pseudo_header_order,
            h3_pseudo_header_order=h3_pseudo_header_order,
            default_headers=default_headers,
            connect_headers=connect_headers,
            certificate_pinning_hosts=certificate_pinning_hosts,
            with_default_bad_pin_handler=with_default_bad_pin_handler,
            request_cookies=request_cookies,
            custom_tls_client=custom_tls_client,
            client_certificates=client_certificates,
            max_idle_connections=max_idle_connections,
            max_idle_connections_per_host=max_idle_connections_per_host,
            max_connections_per_host=max_connections_per_host,
            disable_keep_alives=disable_keep_alives,
            disable_compression=disable_compression,
            idle_conn_timeout_seconds=idle_conn_timeout_seconds,
            max_response_header_bytes=max_response_header_bytes,
            write_buffer_size=write_buffer_size,
            read_buffer_size=read_buffer_size,
            disable_ipv4=disable_ipv4,
            disable_ipv6=disable_ipv6,
            allow_empty_cookies=allow_empty_cookies,
            without_cookie_jar=without_cookie_jar,
            catch_panics=catch_panics,
            with_debug=with_debug,
        )

    # -- attribute delegation → underlying Session ------------------------
    # Allows:  async_session.headers = {...}
    #          async_session.proxy = "http://..."
    #          async_session.cookies = {...}
    # All readable/writable Session properties are transparently delegated.

    def __getattr__(self, name: str) -> Any:
        # Delegate non-private attribute access to the underlying Session.
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self._session, name)

    def __setattr__(self, name: str, value: Any) -> None:
        # Delegate non-private attribute writes to the underlying Session.
        if name.startswith("_"):
            super().__setattr__(name, value)
        else:
            setattr(self._session, name, value)

    async def __aenter__(self) -> "AsyncSession":
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass

    async def _execute_async(self, method: str, url: str, **kwargs: Any) -> Response:
        ffi, lib = _get_ffi()
        callback = _get_async_callback(ffi, lib)
        loop = asyncio.get_running_loop()

        # Build RequestOptions (same as sync path)
        keep_alive: list = []
        opts = ffi.new("RequestOptions *")
        keep_alive.append(opts)

        c_method = ffi.new("char[]", method.encode("utf-8"))
        c_url = ffi.new("char[]", url.encode("utf-8"))
        keep_alive.extend([c_method, c_url])
        opts.method = c_method
        opts.url = c_url

        # Headers
        headers = kwargs.pop("headers", None)
        hdr_ptr, hdr_len = _build_headers(ffi, headers, keep_alive)
        opts.headers = hdr_ptr
        opts.headers_len = hdr_len

        header_order = kwargs.pop("header_order", None)
        ho_ptr, ho_len = _build_string_array(ffi, header_order, keep_alive)
        opts.header_order = ho_ptr
        opts.header_order_len = ho_len

        # Body (zero-copy — ffi.from_buffer avoids copying Python bytes to C heap)
        body = kwargs.pop("body", None)
        if body is not None:
            body_ptr = ffi.from_buffer(body)
            keep_alive.append(body_ptr)
            opts.body = body_ptr
            opts.body_len = len(body)

        # Overrides (use defaults from the session, overridden by kwargs)
        def _val(name: str, as_bool: bool = False):
            v = kwargs.pop(name, None)
            if v is None:
                v = self._session.defaults.get(name)
            if as_bool:
                return 1 if v else 0
            return v

        opts.timeout_seconds = _val("timeout_seconds")
        opts.timeout_milliseconds = _val("timeout_milliseconds")
        opts.follow_redirects = _val("follow_redirects", True)
        opts.insecure_skip_verify = _val("insecure_skip_verify", True)
        opts.force_http1 = _val("force_http1", True)
        opts.with_random_tls_extension_order = _val("with_random_tls_extension_order", True)
        opts.with_protocol_racing = _val("with_protocol_racing", True)
        opts.max_idle_connections = _val("max_idle_connections")
        opts.max_idle_connections_per_host = _val("max_idle_connections_per_host")
        opts.max_connections_per_host = _val("max_connections_per_host")
        opts.disable_keep_alives = _val("disable_keep_alives", True)
        opts.disable_compression = _val("disable_compression", True)
        opts.idle_conn_timeout_seconds = _val("idle_conn_timeout_seconds")
        opts.max_response_header_bytes = _val("max_response_header_bytes")
        opts.write_buffer_size = _val("write_buffer_size")
        opts.read_buffer_size = _val("read_buffer_size")
        opts.allow_empty_cookies = _val("allow_empty_cookies", True)
        opts.without_cookie_jar = _val("without_cookie_jar", True)
        opts.disable_http3 = _val("disable_http3", True)
        opts.disable_ipv4 = _val("disable_ipv4", True)
        opts.disable_ipv6 = _val("disable_ipv6", True)
        opts.catch_panics = _val("catch_panics", True)
        opts.with_debug = _val("with_debug", True)

        # String fields
        for name, field in [
            ("client_identifier", "client_identifier"),
            ("proxy", "proxy"),
            ("server_name_overwrite", "server_name_overwrite"),
            ("request_host_override", "request_host_override"),
            ("local_address", "local_address"),
        ]:
            c_val = _c_string(ffi, _val(name))
            setattr(opts, field, c_val)
            if c_val != ffi.NULL:
                keep_alive.append(c_val)

        # Pseudo-header orders
        pho = _val("pseudo_header_order")
        ph_ptr, ph_len = _build_string_array(ffi, pho, keep_alive)
        opts.pseudo_header_order = ph_ptr
        opts.pseudo_header_order_len = ph_len

        h3pho = _val("h3_pseudo_header_order")
        h3ph_ptr, h3ph_len = _build_string_array(ffi, h3pho, keep_alive)
        opts.h3_pseudo_header_order = h3ph_ptr
        opts.h3_pseudo_header_order_len = h3ph_len

        # Default/connect headers
        dh = _val("default_headers")
        dh_ptr, dh_len = _build_headers(ffi, dh, keep_alive)
        opts.default_headers = dh_ptr
        opts.default_headers_len = dh_len

        ch = _val("connect_headers")
        ch_ptr, ch_len = _build_headers(ffi, ch, keep_alive)
        opts.connect_headers = ch_ptr
        opts.connect_headers_len = ch_len

        # Certificate pinning
        cp = _val("certificate_pinning_hosts")
        cp_ptr, cp_len = _build_pin_entries(ffi, cp, keep_alive)
        opts.certificate_pinning_hosts = cp_ptr
        opts.certificate_pinning_hosts_len = cp_len
        opts.with_default_bad_pin_handler = _val("with_default_bad_pin_handler", True)

        # Request cookies
        rc = _val("request_cookies")
        rc_ptr, rc_len = _build_headers(ffi, rc, keep_alive)
        opts.request_cookies = rc_ptr
        opts.request_cookies_len = rc_len

        # Client certificates
        cc = _val("client_certificates")
        cc_ptr, cc_len = _build_client_certificates(ffi, cc, keep_alive)
        opts.client_certificates = cc_ptr
        opts.client_certificates_len = cc_len

        # Custom TLS client
        ctc = _val("custom_tls_client")
        ctc_ptr = _build_custom_tls_client(ffi, ctc, keep_alive)
        opts.custom_tls_client = ctc_ptr

        # Pre-compute cache key hash and attach to opts (avoids ~50 CGO calls on hit).
        # Use kwargs.get() (non-destructive) so later _val() calls still find overrides.
        def _ck(name):  return kwargs.get(name, self._session.defaults.get(name))
        def _ckb(name): v = kwargs.get(name, self._session.defaults.get(name)); return 1 if v else 0
        ck_hash = _compute_cache_key_hash({
            "client_identifier": _ck("client_identifier") or "",
            "proxy": _ck("proxy") or "",
            "server_name_overwrite": _ck("server_name_overwrite") or "",
            "local_address": _ck("local_address") or "",
            "insecure_skip_verify": _ckb("insecure_skip_verify"),
            "force_http1": _ckb("force_http1"),
            "with_random_tls_extension_order": _ckb("with_random_tls_extension_order"),
            "with_protocol_racing": _ckb("with_protocol_racing"),
            "max_idle_connections": _ck("max_idle_connections"),
            "max_idle_connections_per_host": _ck("max_idle_connections_per_host"),
            "max_connections_per_host": _ck("max_connections_per_host"),
            "max_response_header_bytes": _ck("max_response_header_bytes"),
            "write_buffer_size": _ck("write_buffer_size"),
            "read_buffer_size": _ck("read_buffer_size"),
            "idle_conn_timeout_seconds": _ck("idle_conn_timeout_seconds"),
            "disable_keep_alives": _ckb("disable_keep_alives"),
            "disable_compression": _ckb("disable_compression"),
            "disable_http3": _ckb("disable_http3"),
            "disable_ipv4": _ckb("disable_ipv4"),
            "disable_ipv6": _ckb("disable_ipv6"),
            "follow_redirects": _ckb("follow_redirects"),
            "without_cookie_jar": _ckb("without_cookie_jar"),
            "allow_empty_cookies": _ckb("allow_empty_cookies"),
            "with_default_bad_pin_handler": _ckb("with_default_bad_pin_handler"),
            "timeout_seconds": _ck("timeout_seconds"),
            "timeout_milliseconds": _ck("timeout_milliseconds"),
            "pseudo_header_order": _ck("pseudo_header_order"),
            "h3_pseudo_header_order": _ck("h3_pseudo_header_order"),
            "default_headers": _ck("default_headers"),
            "connect_headers": _ck("connect_headers"),
            "certificate_pinning_hosts": _ck("certificate_pinning_hosts"),
            "client_certificates": _ck("client_certificates"),
            "custom_tls_client": _ck("custom_tls_client"),
        })
        c_ck = _c_string(ffi, ck_hash)
        if c_ck != ffi.NULL:
            keep_alive.append(c_ck)
        opts.cache_key_hash = c_ck

        # ---- streaming fields (injected by stream_to_file) -----------------
        stream_path = kwargs.pop("_stream_output_path", ffi.NULL)
        stream_bs = kwargs.pop("_stream_output_block_size", 0)
        stream_eof = kwargs.pop("_stream_output_eof_symbol", ffi.NULL)
        stream_keep = kwargs.pop("_stream_keep_alive", None)
        if stream_keep is not None:
            keep_alive.extend(stream_keep)
        opts.stream_output_path = stream_path
        opts.stream_output_block_size = stream_bs
        opts.stream_output_eof_symbol = stream_eof

        # ── Register Future with defensive timeout ────────────────────────
        # Go's RequestAsync has its own timeout (timeout_seconds / timeout_milliseconds),
        # but if the Go goroutine hangs indefinitely (network partition, OS bug),
        # the _pending_requests entry would leak the Future + keep_alive forever.
        # A defensive timeout (2× Go timeout + 10 s grace, clamped [60, 600] s)
        # cleans up zombie entries so the Python process does not accumulate
        # leaked memory under high-concurrency workloads.
        go_timeout = float(opts.timeout_seconds) if opts.timeout_seconds > 0 else 30.0
        if opts.timeout_milliseconds > 0:
            go_timeout = float(opts.timeout_milliseconds) / 1000.0
        safe_timeout = max(60.0, min(go_timeout * 2.0 + 10.0, 600.0))

        def _on_zombie_timeout(rid: int) -> None:
            # Safe: by this point the Go goroutine has either completed
            # (callback fired) or is hung.  If completed, _pending_requests
            # already popped and we return early.  If hung, the goroutine
            # owns its own body copy (deepCopyRequestOptions copies via
            # C.GoBytes — Bug #5 fix), so releasing keep_alive is safe.
            with _pending_lock:
                entry = _pending_requests.pop(rid, None)
            if entry is None:
                return  # already resolved via callback
            fut, _ka, _ = entry
            if not fut.done():
                try:
                    fut.get_loop().call_soon_threadsafe(
                        fut.set_exception,
                        asyncio.TimeoutError(
                            f"Async request {rid} did not complete within "
                            f"{safe_timeout:.0f}s — Go goroutine may be hung"
                        ),
                    )
                except RuntimeError:
                    # Event loop closed — nothing can be done (graceful shutdown).
                    pass

        request_id = _next_request_id()
        future: asyncio.Future = loop.create_future()
        timeout_handle = loop.call_later(safe_timeout, _on_zombie_timeout, request_id)

        with _pending_lock:
            # Store keep_alive alongside the Future — the goroutine reads
            # from C memory via unsafe.Slice, so Python must keep the
            # original buffers alive until the callback fires.
            _pending_requests[request_id] = (future, keep_alive, timeout_handle)

        # Step 1-2: Call RequestAsync — Go deep-copies, dispatches goroutine,
        # returns immediately.  Python can free keep_alive memory after return.
        ret = lib.RequestAsync(opts, request_id, callback)

        if ret != 0:
            # RequestAsync returned an error — clean up the pending entry
            # and cancel the defensive zombie timeout.  keep_alive is
            # already safe to release because RequestAsync deep-copies
            # before returning.
            with _pending_lock:
                entry = _pending_requests.pop(request_id, None)
                if entry is not None:
                    _, _, th = entry
                    th.cancel()
            raise RuntimeError("RequestAsync failed — opts or callback is nil")

        # Await the Future — event loop is free to run other tasks
        return await future

    async def stream_to_file(
        self,
        # HTTP 方法 / HTTP method
        method: str,
        # 请求 URL / Request URL
        url: str,
        # 输出文件路径 / Output file path
        output_path: str,
        *,
        # 请求头字典 / Request headers dict
        headers: Optional[Dict[str, str]] = None,
        # 请求头发送顺序 / Header send order
        header_order: Optional[List[str]] = None,
        # 请求体原始字节串 / Request body as raw bytes
        body: Optional[bytes] = None,
        # 块大小（字节） / Chunk size per read (bytes)
        chunk_size: int = 8192,
        # 可选的 EOF 标记字符串 / Optional EOF marker string
        eof_marker: Optional[str] = None,
        **kwargs: Any,
    ) -> Response:
        """执行请求并将响应体流式写入磁盘（异步）。

        Execute a request and stream the response body to disk (async).
        """
        ffi, _ = _get_ffi()

        keep_alive: list = []
        c_path = _c_string(ffi, output_path)
        keep_alive.append(c_path)

        c_eof = _c_string(ffi, eof_marker)
        if c_eof != ffi.NULL:
            keep_alive.append(c_eof)

        return await self._execute_async(
            method,
            url,
            headers=headers,
            header_order=header_order,
            body=body,
            _stream_output_path=c_path,
            _stream_output_block_size=chunk_size,
            _stream_output_eof_symbol=c_eof,
            _stream_keep_alive=keep_alive,
            **kwargs,
        )

    async def execute_request(
        self,
        # HTTP 方法 / HTTP method
        method: str,
        # 完整的请求 URL / Full request URL including scheme and hostname
        url: str,
        *,
        # 请求头字典 / Request headers dict
        headers: Optional[Dict[str, str]] = None,
        # 请求头的发送顺序列表 / Header send-order list
        header_order: Optional[List[str]] = None,
        # 请求体原始字节串 / Request body as raw bytes
        body: Optional[bytes] = None,
        # ── 每请求覆盖参数 / Per-request overrides ──
        # 覆盖 TLS 指纹标识 / Override TLS fingerprint identifier
        client_identifier: Optional[str] = None,
        # 覆盖超时时间（秒） / Override timeout (seconds)
        timeout: Optional[int] = None,
        # 覆盖超时时间（毫秒） / Override timeout (milliseconds)
        timeout_milliseconds: Optional[int] = None,
        # 覆盖重定向跟随策略 / Override redirect-following policy
        follow_redirects: Optional[bool] = None,
        # 覆盖 TLS 证书校验 / Override TLS certificate verification
        verify: Optional[bool] = None,
        # 覆盖 HTTP/1.1 强制开关 / Override force HTTP/1.1
        force_http1: Optional[bool] = None,
        # 覆盖 TLS 扩展随机化 / Override TLS extension randomisation
        random_tls_extension_order: Optional[bool] = None,
        # 覆盖协议竞速开关 / Override protocol racing
        with_protocol_racing: Optional[bool] = None,
        # 覆盖 SNI 主机名 / Override SNI hostname
        server_name_overwrite: Optional[str] = None,
        # 覆盖 HTTP Host 请求头 / Override HTTP Host header
        request_host_override: Optional[str] = None,
        # 覆盖代理 URL / Override proxy URL
        proxy: Optional[str] = None,
        # 覆盖本地绑定地址 / Override local bind address
        local_address: Optional[str] = None,
        # 覆盖 HTTP/2 伪头顺序 / Override HTTP/2 pseudo-header order
        pseudo_header_order: Optional[List[str]] = None,
        # 覆盖 HTTP/3 伪头顺序 / Override HTTP/3 pseudo-header order
        h3_pseudo_header_order: Optional[List[str]] = None,
        # 覆盖默认请求头字典 / Override default headers dict
        default_headers: Optional[Dict[str, str]] = None,
        # 覆盖代理 CONNECT 隧道请求头 / Override proxy CONNECT tunnel headers
        connect_headers: Optional[Dict[str, str]] = None,
        # 覆盖 SSL 证书固定字典 / Override SSL certificate pinning dict
        certificate_pinning_hosts: Optional[Dict[str, List[str]]] = None,
        # 覆盖 Bad-Pin 处理器开关 / Override default bad-pin handler toggle
        with_default_bad_pin_handler: Optional[bool] = None,
        # 覆盖预置 Cookie 字典 / Override pre-populated cookie dict
        request_cookies: Optional[Dict[str, str]] = None,
        # 覆盖客户端证书列表 / Override client certificate list
        client_certificates: Optional[List[Dict[str, bytes]]] = None,
        # 覆盖自定义 TLS 客户端配置 / Override custom TLS client configuration
        custom_tls_client: Optional[Dict[str, Any]] = None,
        # 覆盖全局最大空闲连接数 / Override global max idle connections
        max_idle_connections: Optional[int] = None,
        # 覆盖每 Host 最大空闲连接数 / Override max idle connections per host
        max_idle_connections_per_host: Optional[int] = None,
        # 覆盖每 Host 最大总连接数 / Override max total connections per host
        max_connections_per_host: Optional[int] = None,
        # 覆盖 Keep-Alive 禁用 / Override disable Keep-Alive
        disable_keep_alives: Optional[bool] = None,
        # 覆盖压缩禁用 / Override disable compression
        disable_compression: Optional[bool] = None,
        # 覆盖空闲连接超时 / Override idle connection timeout
        idle_conn_timeout_seconds: Optional[int] = None,
        # 覆盖响应头最大字节数 / Override max response header bytes
        max_response_header_bytes: Optional[int] = None,
        # 覆盖写缓冲区大小 / Override write buffer size
        write_buffer_size: Optional[int] = None,
        # 覆盖读缓冲区大小 / Override read buffer size
        read_buffer_size: Optional[int] = None,
        # 覆盖空 Cookie 允许 / Override allow-empty-cookies
        allow_empty_cookies: Optional[bool] = None,
        # 覆盖禁用 Cookie Jar / Override disable Cookie Jar
        without_cookie_jar: Optional[bool] = None,
        # 覆盖 HTTP/3 禁用 / Override disable HTTP/3
        disable_http3: Optional[bool] = None,
        # 覆盖 IPv4 禁用 / Override disable IPv4
        disable_ipv4: Optional[bool] = None,
        # 覆盖 IPv6 禁用 / Override disable IPv6
        disable_ipv6: Optional[bool] = None,
        # 覆盖 panic 捕获 / Override catch-panics
        catch_panics: Optional[bool] = None,
        # 覆盖调试日志 / Override debug logging
        with_debug: Optional[bool] = None,
        **kwargs: Any,
    ) -> Response:
        """通过 Go 引擎执行单次 HTTP 请求（异步）。

        Execute a single HTTP request through the Go engine (async).
        """
        # Remap user-facing names → defaults-dict keys where they differ.
        # timeout → timeout_seconds
        # verify → insecure_skip_verify (inverted: True→0, False→1)
        # random_tls_extension_order → with_random_tls_extension_order
        return await self._execute_async(
            method, url,
            headers=headers, header_order=header_order, body=body,
            timeout_seconds=timeout,
            insecure_skip_verify=None if verify is None else (0 if verify else 1),
            with_random_tls_extension_order=random_tls_extension_order,
            client_identifier=client_identifier,
            timeout_milliseconds=timeout_milliseconds, follow_redirects=follow_redirects,
            force_http1=force_http1,
            with_protocol_racing=with_protocol_racing,
            server_name_overwrite=server_name_overwrite,
            request_host_override=request_host_override, proxy=proxy,
            local_address=local_address, pseudo_header_order=pseudo_header_order,
            h3_pseudo_header_order=h3_pseudo_header_order,
            default_headers=default_headers, connect_headers=connect_headers,
            certificate_pinning_hosts=certificate_pinning_hosts,
            with_default_bad_pin_handler=with_default_bad_pin_handler,
            request_cookies=request_cookies, client_certificates=client_certificates,
            custom_tls_client=custom_tls_client,
            max_idle_connections=max_idle_connections,
            max_idle_connections_per_host=max_idle_connections_per_host,
            max_connections_per_host=max_connections_per_host,
            disable_keep_alives=disable_keep_alives,
            disable_compression=disable_compression,
            idle_conn_timeout_seconds=idle_conn_timeout_seconds,
            max_response_header_bytes=max_response_header_bytes,
            write_buffer_size=write_buffer_size, read_buffer_size=read_buffer_size,
            allow_empty_cookies=allow_empty_cookies,
            without_cookie_jar=without_cookie_jar,
            disable_http3=disable_http3, disable_ipv4=disable_ipv4,
            disable_ipv6=disable_ipv6, catch_panics=catch_panics,
            with_debug=with_debug,
            **kwargs,
        )

    async def typed_request(self, req: Request) -> Response:
        """使用 :class:`Request` 强类型对象执行 HTTP 请求（异步）。

        Execute an HTTP request using a :class:`Request` strongly-typed object (async).
        """
        method = req["method"]
        url = req["url"]
        kwargs = {k: v for k, v in req.items() if k not in ("method", "url")}
        return await self.execute_request(method, url, **kwargs)

    async def get(self, url: str, *, headers: Optional[Dict[str, str]] = None, **kwargs: Any) -> Response:
        return await self.execute_request("GET", url, headers=headers, **kwargs)

    async def post(self, url: str, *, headers: Optional[Dict[str, str]] = None, body: Optional[bytes] = None, **kwargs: Any) -> Response:
        return await self.execute_request("POST", url, headers=headers, body=body, **kwargs)

    async def head(self, url: str, *, headers: Optional[Dict[str, str]] = None, **kwargs: Any) -> Response:
        return await self.execute_request("HEAD", url, headers=headers, **kwargs)

    async def put(self, url: str, *, headers: Optional[Dict[str, str]] = None, body: Optional[bytes] = None, **kwargs: Any) -> Response:
        return await self.execute_request("PUT", url, headers=headers, body=body, **kwargs)

    async def delete(self, url: str, *, headers: Optional[Dict[str, str]] = None, **kwargs: Any) -> Response:
        return await self.execute_request("DELETE", url, headers=headers, **kwargs)

    async def patch(self, url: str, *, headers: Optional[Dict[str, str]] = None, body: Optional[bytes] = None, **kwargs: Any) -> Response:
        return await self.execute_request("PATCH", url, headers=headers, body=body, **kwargs)

    @staticmethod
    def clear_client_pool() -> None:
        """Close all idle connections in the global Go client pool.

        Calls the Go C function directly.  ClearClientPool iterates the
        internal client map and closes idle connections — it is fast and
        non-blocking, so no thread pool is needed (Constraint 4).
        """
        _, lib = _get_ffi()
        lib.ClearClientPool()


# Convenience top-level function
def clear_client_pool() -> None:
    """Close all idle connections in the global Go client pool (synchronous)."""
    Session.clear_client_pool()
