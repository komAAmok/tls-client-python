"""Generated explicit surface for the requests-compatible facade.

DO NOT EDIT BY HAND.  Regenerate with::

    python3 tools/gen_requests_surface.py

This module holds the mechanical part of the facade: the literal property
definitions for every session-level TLS knob, and the literal signatures of
request() plus the seven verb helpers.  Everything here is derived from the
native tls_client._core.Session signature, so IDEs, inspect and static
analysis see exactly the knobs the engine accepts.  The behavioural half
lives in tls_client/sessions.py.
"""

from typing import Any, Dict, List, Optional, Tuple, Union  # noqa: F401

from tls_client._core import (  # noqa: F401
    ClientIdentifiers,
    ProxyConfig,
)

#: Every session-level TLS knob, in native declaration order.
TLS_SESSION_OPTION_NAMES = (
    "client_identifier",
    "force_http1",
    "disable_http3",
    "with_protocol_racing",
    "random_tls_extension_order",
    "timeout_milliseconds",
    "server_name_overwrite",
    "local_address",
    "request_host_override",
    "pseudo_header_order",
    "h3_pseudo_header_order",
    "default_headers",
    "connect_headers",
    "certificate_pinning_hosts",
    "with_default_bad_pin_handler",
    "request_cookies",
    "custom_tls_client",
    "client_certificates",
    "max_idle_connections",
    "max_idle_connections_per_host",
    "max_connections_per_host",
    "disable_keep_alives",
    "disable_compression",
    "idle_conn_timeout_seconds",
    "max_response_header_bytes",
    "write_buffer_size",
    "read_buffer_size",
    "disable_ipv4",
    "disable_ipv6",
    "tcp_ttl",
    "tcp_window_size",
    "tcp_window_scale",
    "tcp_mss",
    "allow_empty_cookies",
    "without_cookie_jar",
    "catch_panics",
    "with_debug",
    "disable_session_tickets",
    "tls_keylog_path",
    "root_ca_pem",
    "h2_max_data_frame_size",
    "preface_ping_idle_ms",
    "hpack_indexing_policy",
    "cookie_crumb",
    "extension_permute_mode",
    "extension_permute_prefix",
    "h2_disable_priority_frames",
    "header_order_by_dest",
    "header_order_dest",
    "tcp_dont_fragment",
    "tcp_tos",
    "tcp_no_delay",
    "tcp_window_clamp",
    "tcp_ip_id_mode",
)

#: Native default of every session-level TLS knob.
TLS_SESSION_OPTION_DEFAULTS = {
    "client_identifier": 'chrome_120',
    "force_http1": False,
    "disable_http3": False,
    "with_protocol_racing": False,
    "random_tls_extension_order": True,
    "timeout_milliseconds": 0,
    "server_name_overwrite": None,
    "local_address": None,
    "request_host_override": None,
    "pseudo_header_order": None,
    "h3_pseudo_header_order": None,
    "default_headers": None,
    "connect_headers": None,
    "certificate_pinning_hosts": None,
    "with_default_bad_pin_handler": False,
    "request_cookies": None,
    "custom_tls_client": None,
    "client_certificates": None,
    "max_idle_connections": 0,
    "max_idle_connections_per_host": 0,
    "max_connections_per_host": 0,
    "disable_keep_alives": False,
    "disable_compression": False,
    "idle_conn_timeout_seconds": 0,
    "max_response_header_bytes": 0,
    "write_buffer_size": 0,
    "read_buffer_size": 0,
    "disable_ipv4": False,
    "disable_ipv6": False,
    "tcp_ttl": 0,
    "tcp_window_size": 0,
    "tcp_window_scale": 0,
    "tcp_mss": 0,
    "allow_empty_cookies": False,
    "without_cookie_jar": False,
    "catch_panics": True,
    "with_debug": False,
    "disable_session_tickets": False,
    "tls_keylog_path": None,
    "root_ca_pem": None,
    "h2_max_data_frame_size": 0,
    "preface_ping_idle_ms": 0,
    "hpack_indexing_policy": '',
    "cookie_crumb": False,
    "extension_permute_mode": 0,
    "extension_permute_prefix": 0,
    "h2_disable_priority_frames": False,
    "header_order_by_dest": False,
    "header_order_dest": None,
    "tcp_dont_fragment": -1,
    "tcp_tos": -1,
    "tcp_no_delay": -1,
    "tcp_window_clamp": 0,
    "tcp_ip_id_mode": '',
}

#: Every per-request TLS override accepted by request() and the verbs.
TLS_REQUEST_OPTION_NAMES = (
    "client_identifier",
    "force_http1",
    "disable_http3",
    "with_protocol_racing",
    "random_tls_extension_order",
    "timeout_milliseconds",
    "server_name_overwrite",
    "local_address",
    "request_host_override",
    "pseudo_header_order",
    "h3_pseudo_header_order",
    "default_headers",
    "connect_headers",
    "certificate_pinning_hosts",
    "with_default_bad_pin_handler",
    "request_cookies",
    "custom_tls_client",
    "client_certificates",
    "max_idle_connections",
    "max_idle_connections_per_host",
    "max_connections_per_host",
    "disable_keep_alives",
    "disable_compression",
    "idle_conn_timeout_seconds",
    "max_response_header_bytes",
    "write_buffer_size",
    "read_buffer_size",
    "disable_ipv4",
    "disable_ipv6",
    "tcp_ttl",
    "tcp_window_size",
    "tcp_window_scale",
    "tcp_mss",
    "allow_empty_cookies",
    "without_cookie_jar",
    "catch_panics",
    "with_debug",
    "disable_session_tickets",
    "tls_keylog_path",
    "root_ca_pem",
    "h2_max_data_frame_size",
    "preface_ping_idle_ms",
    "hpack_indexing_policy",
    "cookie_crumb",
    "extension_permute_mode",
    "extension_permute_prefix",
    "h2_disable_priority_frames",
    "header_order_by_dest",
    "header_order_dest",
    "tcp_dont_fragment",
    "tcp_tos",
    "tcp_no_delay",
    "tcp_window_clamp",
    "tcp_ip_id_mode",
    "header_order",
)

#: Attributes requests.Session owns; they never reach the engine directly.
REQUESTS_OWNED_ATTRIBUTES = (
    "auth",
    "cert",
    "cookies",
    "headers",
    "hooks",
    "max_redirects",
    "params",
    "proxies",
    "stream",
    "trust_env",
    "verify",
)

#: Native knobs the facade re-interprets; see tls_client/sessions.py.
SPECIAL_OPTION_NAMES = (
    "fingerprint",
    "follow_redirects",
    "proxy",
    "timeout",
)


def collect_tls_options(namespace, names=TLS_REQUEST_OPTION_NAMES):
    """Return the TLS overrides actually supplied in *namespace*.

    None means 'inherit from the session', so those entries are dropped; an
    explicit False or 0 is a real override and is kept.
    """
    options = {}
    for name in names:
        value = namespace.get(name)
        if value is not None:
            options[name] = value
    return options


class TLSOptionsMixin:
    """Read/write session-level TLS knobs, mirroring the native defaults."""

    @property
    def client_identifier(self) -> ClientIdentifiers:
        """TLS 指纹标识 / TLS fingerprint identifier."""
        return self._get_tls_option("client_identifier")

    @client_identifier.setter
    def client_identifier(self, value: ClientIdentifiers) -> None:
        self._set_tls_option("client_identifier", value)

    @property
    def force_http1(self) -> bool:
        """是否强制 HTTP/1.1 / Whether to force HTTP/1.1."""
        return self._get_tls_option("force_http1")

    @force_http1.setter
    def force_http1(self, value: bool) -> None:
        self._set_tls_option("force_http1", value)

    @property
    def disable_http3(self) -> bool:
        """是否完全禁用 HTTP/3 / Whether to disable HTTP/3."""
        return self._get_tls_option("disable_http3")

    @disable_http3.setter
    def disable_http3(self, value: bool) -> None:
        self._set_tls_option("disable_http3", value)

    @property
    def with_protocol_racing(self) -> bool:
        """是否启用协议竞速 / Whether to enable protocol racing."""
        return self._get_tls_option("with_protocol_racing")

    @with_protocol_racing.setter
    def with_protocol_racing(self, value: bool) -> None:
        self._set_tls_option("with_protocol_racing", value)

    @property
    def random_tls_extension_order(self) -> bool:
        """是否随机 TLS 扩展顺序 / Whether to randomise TLS extension order."""
        return self._get_tls_option("random_tls_extension_order")

    @random_tls_extension_order.setter
    def random_tls_extension_order(self, value: bool) -> None:
        self._set_tls_option("random_tls_extension_order", value)

    @property
    def timeout_milliseconds(self) -> int:
        """请求超时时间（毫秒） / Request timeout in milliseconds."""
        return self._get_tls_option("timeout_milliseconds")

    @timeout_milliseconds.setter
    def timeout_milliseconds(self, value: int) -> None:
        self._set_tls_option("timeout_milliseconds", value)

    @property
    def server_name_overwrite(self) -> Optional[str]:
        """SNI 主机名覆盖 / SNI hostname override."""
        return self._get_tls_option("server_name_overwrite")

    @server_name_overwrite.setter
    def server_name_overwrite(self, value: Optional[str]) -> None:
        self._set_tls_option("server_name_overwrite", value)

    @property
    def local_address(self) -> Optional[str]:
        """本地绑定地址 / Local bind address."""
        return self._get_tls_option("local_address")

    @local_address.setter
    def local_address(self, value: Optional[str]) -> None:
        self._set_tls_option("local_address", value)

    @property
    def request_host_override(self) -> Optional[str]:
        """Host 请求头覆盖 / Host header override."""
        return self._get_tls_option("request_host_override")

    @request_host_override.setter
    def request_host_override(self, value: Optional[str]) -> None:
        self._set_tls_option("request_host_override", value)

    @property
    def pseudo_header_order(self) -> Optional[List[str]]:
        """HTTP/2 伪头顺序 / HTTP/2 pseudo-header order."""
        return self._get_tls_option("pseudo_header_order")

    @pseudo_header_order.setter
    def pseudo_header_order(self, value: Optional[List[str]]) -> None:
        self._set_tls_option("pseudo_header_order", value)

    @property
    def h3_pseudo_header_order(self) -> Optional[List[str]]:
        """HTTP/3 伪头顺序 / HTTP/3 pseudo-header order."""
        return self._get_tls_option("h3_pseudo_header_order")

    @h3_pseudo_header_order.setter
    def h3_pseudo_header_order(self, value: Optional[List[str]]) -> None:
        self._set_tls_option("h3_pseudo_header_order", value)

    @property
    def default_headers(self) -> Optional[Dict[str, str]]:
        """默认请求头字典 / Default headers dict."""
        return self._get_tls_option("default_headers")

    @default_headers.setter
    def default_headers(self, value: Optional[Dict[str, str]]) -> None:
        self._set_tls_option("default_headers", value)

    @property
    def connect_headers(self) -> Optional[Dict[str, str]]:
        """代理 CONNECT 隧道请求头字典 / Proxy CONNECT tunnel headers."""
        return self._get_tls_option("connect_headers")

    @connect_headers.setter
    def connect_headers(self, value: Optional[Dict[str, str]]) -> None:
        self._set_tls_option("connect_headers", value)

    @property
    def certificate_pinning_hosts(self) -> Optional[Dict[str, List[str]]]:
        """SSL 证书固定字典 / SSL certificate pinning dict."""
        return self._get_tls_option("certificate_pinning_hosts")

    @certificate_pinning_hosts.setter
    def certificate_pinning_hosts(self, value: Optional[Dict[str, List[str]]]) -> None:
        self._set_tls_option("certificate_pinning_hosts", value)

    @property
    def with_default_bad_pin_handler(self) -> bool:
        """是否调用默认 Bad-Pin 处理器 / Whether to invoke the default bad-pin handler."""
        return self._get_tls_option("with_default_bad_pin_handler")

    @with_default_bad_pin_handler.setter
    def with_default_bad_pin_handler(self, value: bool) -> None:
        self._set_tls_option("with_default_bad_pin_handler", value)

    @property
    def request_cookies(self) -> Optional[Dict[str, str]]:
        """预置 Cookie 字典 / Pre-populated cookie dict."""
        return self._get_tls_option("request_cookies")

    @request_cookies.setter
    def request_cookies(self, value: Optional[Dict[str, str]]) -> None:
        self._set_tls_option("request_cookies", value)

    @property
    def custom_tls_client(self) -> Optional[Dict[str, Any]]:
        """完全自定义的 TLS 客户端配置 / Fully custom TLS client configuration."""
        return self._get_tls_option("custom_tls_client")

    @custom_tls_client.setter
    def custom_tls_client(self, value: Optional[Dict[str, Any]]) -> None:
        self._set_tls_option("custom_tls_client", value)

    @property
    def client_certificates(self) -> Optional[List[Dict[str, bytes]]]:
        """客户端证书列表 (mTLS) / Client certificates for mTLS."""
        return self._get_tls_option("client_certificates")

    @client_certificates.setter
    def client_certificates(self, value: Optional[List[Dict[str, bytes]]]) -> None:
        self._set_tls_option("client_certificates", value)

    @property
    def max_idle_connections(self) -> int:
        """全局最大空闲连接数 / Global max idle connections."""
        return self._get_tls_option("max_idle_connections")

    @max_idle_connections.setter
    def max_idle_connections(self, value: int) -> None:
        self._set_tls_option("max_idle_connections", value)

    @property
    def max_idle_connections_per_host(self) -> int:
        """每 Host 最大空闲连接数 / Max idle connections per host."""
        return self._get_tls_option("max_idle_connections_per_host")

    @max_idle_connections_per_host.setter
    def max_idle_connections_per_host(self, value: int) -> None:
        self._set_tls_option("max_idle_connections_per_host", value)

    @property
    def max_connections_per_host(self) -> int:
        """每 Host 最大总连接数 / Max total connections per host."""
        return self._get_tls_option("max_connections_per_host")

    @max_connections_per_host.setter
    def max_connections_per_host(self, value: int) -> None:
        self._set_tls_option("max_connections_per_host", value)

    @property
    def disable_keep_alives(self) -> bool:
        """是否禁用 Keep-Alive / Whether to disable Keep-Alive."""
        return self._get_tls_option("disable_keep_alives")

    @disable_keep_alives.setter
    def disable_keep_alives(self, value: bool) -> None:
        self._set_tls_option("disable_keep_alives", value)

    @property
    def disable_compression(self) -> bool:
        """是否禁用响应解压 / Whether to disable decompression."""
        return self._get_tls_option("disable_compression")

    @disable_compression.setter
    def disable_compression(self, value: bool) -> None:
        self._set_tls_option("disable_compression", value)

    @property
    def idle_conn_timeout_seconds(self) -> int:
        """空闲连接超时（秒） / Idle connection timeout (seconds)."""
        return self._get_tls_option("idle_conn_timeout_seconds")

    @idle_conn_timeout_seconds.setter
    def idle_conn_timeout_seconds(self, value: int) -> None:
        self._set_tls_option("idle_conn_timeout_seconds", value)

    @property
    def max_response_header_bytes(self) -> int:
        """响应头最大字节数 / Max response header bytes."""
        return self._get_tls_option("max_response_header_bytes")

    @max_response_header_bytes.setter
    def max_response_header_bytes(self, value: int) -> None:
        self._set_tls_option("max_response_header_bytes", value)

    @property
    def write_buffer_size(self) -> int:
        """写缓冲区大小 / Write buffer size."""
        return self._get_tls_option("write_buffer_size")

    @write_buffer_size.setter
    def write_buffer_size(self, value: int) -> None:
        self._set_tls_option("write_buffer_size", value)

    @property
    def read_buffer_size(self) -> int:
        """读缓冲区大小 / Read buffer size."""
        return self._get_tls_option("read_buffer_size")

    @read_buffer_size.setter
    def read_buffer_size(self, value: int) -> None:
        self._set_tls_option("read_buffer_size", value)

    @property
    def disable_ipv4(self) -> bool:
        """是否禁用 IPv4 / Whether to disable IPv4."""
        return self._get_tls_option("disable_ipv4")

    @disable_ipv4.setter
    def disable_ipv4(self, value: bool) -> None:
        self._set_tls_option("disable_ipv4", value)

    @property
    def disable_ipv6(self) -> bool:
        """是否禁用 IPv6 / Whether to disable IPv6."""
        return self._get_tls_option("disable_ipv6")

    @disable_ipv6.setter
    def disable_ipv6(self, value: bool) -> None:
        self._set_tls_option("disable_ipv6", value)

    @property
    def tcp_ttl(self) -> int:
        """IP TTL / IP TTL value. 0 = auto from profile."""
        return self._get_tls_option("tcp_ttl")

    @tcp_ttl.setter
    def tcp_ttl(self, value: int) -> None:
        self._set_tls_option("tcp_ttl", value)

    @property
    def tcp_window_size(self) -> int:
        """TCP receive window size. 0 = auto from profile."""
        return self._get_tls_option("tcp_window_size")

    @tcp_window_size.setter
    def tcp_window_size(self, value: int) -> None:
        self._set_tls_option("tcp_window_size", value)

    @property
    def tcp_window_scale(self) -> int:
        """TCP window scale factor. 0 = auto from profile."""
        return self._get_tls_option("tcp_window_scale")

    @tcp_window_scale.setter
    def tcp_window_scale(self, value: int) -> None:
        self._set_tls_option("tcp_window_scale", value)

    @property
    def tcp_mss(self) -> int:
        """TCP Maximum Segment Size. 0 = auto from profile."""
        return self._get_tls_option("tcp_mss")

    @tcp_mss.setter
    def tcp_mss(self, value: int) -> None:
        self._set_tls_option("tcp_mss", value)

    @property
    def allow_empty_cookies(self) -> bool:
        """是否允许空 Cookie / Whether to allow empty cookies."""
        return self._get_tls_option("allow_empty_cookies")

    @allow_empty_cookies.setter
    def allow_empty_cookies(self, value: bool) -> None:
        self._set_tls_option("allow_empty_cookies", value)

    @property
    def without_cookie_jar(self) -> bool:
        """是否禁用 Cookie Jar / Whether to disable Cookie Jar."""
        return self._get_tls_option("without_cookie_jar")

    @without_cookie_jar.setter
    def without_cookie_jar(self, value: bool) -> None:
        self._set_tls_option("without_cookie_jar", value)

    @property
    def catch_panics(self) -> bool:
        """是否捕获 Go panic / Whether to catch Go panics."""
        return self._get_tls_option("catch_panics")

    @catch_panics.setter
    def catch_panics(self, value: bool) -> None:
        self._set_tls_option("catch_panics", value)

    @property
    def with_debug(self) -> bool:
        """是否启用调试日志 / Whether to enable debug logging."""
        return self._get_tls_option("with_debug")

    @with_debug.setter
    def with_debug(self, value: bool) -> None:
        self._set_tls_option("with_debug", value)

    @property
    def disable_session_tickets(self) -> bool:
        """是否禁用 TLS session tickets (ABI 2) / Disable TLS session tickets."""
        return self._get_tls_option("disable_session_tickets")

    @disable_session_tickets.setter
    def disable_session_tickets(self, value: bool) -> None:
        self._set_tls_option("disable_session_tickets", value)

    @property
    def tls_keylog_path(self) -> Optional[str]:
        """TLS keylog 输出路径 (ABI 2) / TLS keylog output path."""
        return self._get_tls_option("tls_keylog_path")

    @tls_keylog_path.setter
    def tls_keylog_path(self, value: Optional[str]) -> None:
        self._set_tls_option("tls_keylog_path", value)

    @property
    def root_ca_pem(self) -> Optional[bytes]:
        """自定义根 CA PEM (ABI 2) / Custom root CA PEM bytes."""
        return self._get_tls_option("root_ca_pem")

    @root_ca_pem.setter
    def root_ca_pem(self, value: Optional[bytes]) -> None:
        self._set_tls_option("root_ca_pem", value)

    @property
    def h2_max_data_frame_size(self) -> int:
        """HTTP/2 DATA 帧上限 (ABI 2.1) / HTTP/2 max DATA frame size."""
        return self._get_tls_option("h2_max_data_frame_size")

    @h2_max_data_frame_size.setter
    def h2_max_data_frame_size(self, value: int) -> None:
        self._set_tls_option("h2_max_data_frame_size", value)

    @property
    def preface_ping_idle_ms(self) -> int:
        """空闲 PING 阈值 (ABI 2.1) / Preface PING idle threshold."""
        return self._get_tls_option("preface_ping_idle_ms")

    @preface_ping_idle_ms.setter
    def preface_ping_idle_ms(self, value: int) -> None:
        self._set_tls_option("preface_ping_idle_ms", value)

    @property
    def hpack_indexing_policy(self) -> str:
        """HPACK 索引策略 (ABI 2.1) / HPACK indexing policy."""
        return self._get_tls_option("hpack_indexing_policy")

    @hpack_indexing_policy.setter
    def hpack_indexing_policy(self, value: str) -> None:
        self._set_tls_option("hpack_indexing_policy", value)

    @property
    def cookie_crumb(self) -> bool:
        """Cookie 拆分 (ABI 2.1) / Split cookies into crumbs."""
        return self._get_tls_option("cookie_crumb")

    @cookie_crumb.setter
    def cookie_crumb(self, value: bool) -> None:
        self._set_tls_option("cookie_crumb", value)

    @property
    def extension_permute_mode(self) -> int:
        """扩展乱序策略: 0=off, 1=chrome, 2=all, 3=prefix (ABI 3)."""
        return self._get_tls_option("extension_permute_mode")

    @extension_permute_mode.setter
    def extension_permute_mode(self, value: int) -> None:
        self._set_tls_option("extension_permute_mode", value)

    @property
    def extension_permute_prefix(self) -> int:
        """前缀长度（仅 mode=3） / Prefix length (mode=3 only)."""
        return self._get_tls_option("extension_permute_prefix")

    @extension_permute_prefix.setter
    def extension_permute_prefix(self, value: int) -> None:
        self._set_tls_option("extension_permute_prefix", value)

    @property
    def h2_disable_priority_frames(self) -> bool:
        """抑制 HTTP/2 PRIORITY 帧 (ABI 3) / Suppress PRIORITY frames."""
        return self._get_tls_option("h2_disable_priority_frames")

    @h2_disable_priority_frames.setter
    def h2_disable_priority_frames(self, value: bool) -> None:
        self._set_tls_option("h2_disable_priority_frames", value)

    @property
    def header_order_by_dest(self) -> bool:
        """按 Sec-Fetch-Dest 选择浏览器真实头序 (ABI 3)."""
        return self._get_tls_option("header_order_by_dest")

    @header_order_by_dest.setter
    def header_order_by_dest(self, value: bool) -> None:
        self._set_tls_option("header_order_by_dest", value)

    @property
    def header_order_dest(self) -> Optional[str]:
        """显式目的类型（留空自动推断） / Explicit Sec-Fetch-Dest value."""
        return self._get_tls_option("header_order_dest")

    @header_order_dest.setter
    def header_order_dest(self, value: Optional[str]) -> None:
        self._set_tls_option("header_order_dest", value)

    @property
    def tcp_dont_fragment(self) -> int:
        """IP DF 位: -1=auto, 0=clear, 1=set (ABI 3)."""
        return self._get_tls_option("tcp_dont_fragment")

    @tcp_dont_fragment.setter
    def tcp_dont_fragment(self, value: int) -> None:
        self._set_tls_option("tcp_dont_fragment", value)

    @property
    def tcp_tos(self) -> int:
        """IP TOS / DSCP 值: -1=auto (ABI 3)."""
        return self._get_tls_option("tcp_tos")

    @tcp_tos.setter
    def tcp_tos(self, value: int) -> None:
        self._set_tls_option("tcp_tos", value)

    @property
    def tcp_no_delay(self) -> int:
        """TCP_NODELAY: -1=auto, 0=off, 1=on (ABI 3)."""
        return self._get_tls_option("tcp_no_delay")

    @tcp_no_delay.setter
    def tcp_no_delay(self, value: int) -> None:
        self._set_tls_option("tcp_no_delay", value)

    @property
    def tcp_window_clamp(self) -> int:
        """TCP 窗口钳制值 (ABI 3) / TCP window clamp."""
        return self._get_tls_option("tcp_window_clamp")

    @tcp_window_clamp.setter
    def tcp_window_clamp(self, value: int) -> None:
        self._set_tls_option("tcp_window_clamp", value)

    @property
    def tcp_ip_id_mode(self) -> str:
        """IP ID 生成模式 (ABI 3) / IP ID generation mode."""
        return self._get_tls_option("tcp_ip_id_mode")

    @tcp_ip_id_mode.setter
    def tcp_ip_id_mode(self, value: str) -> None:
        self._set_tls_option("tcp_ip_id_mode", value)


class TLSVerbMixin:
    """Explicit request()/verb signatures covering every TLS override."""

    def request(
        self,
        method: str,
        url: Any,
        params: Optional[Any] = None,
        data: Optional[Any] = None,
        headers: Optional[Any] = None,
        cookies: Optional[Any] = None,
        files: Optional[Any] = None,
        auth: Optional[Any] = None,
        timeout: Optional[Any] = None,
        allow_redirects: Optional[bool] = None,
        proxies: Optional[Any] = None,
        hooks: Optional[Any] = None,
        stream: Optional[bool] = None,
        verify: Optional[Any] = None,
        cert: Optional[Any] = None,
        json: Optional[Any] = None,
        context: Optional[Any] = None,
        body: Optional[Any] = None,
        *,
        client_identifier: Optional[Any] = None,
        force_http1: Optional[Any] = None,
        disable_http3: Optional[Any] = None,
        with_protocol_racing: Optional[Any] = None,
        random_tls_extension_order: Optional[Any] = None,
        timeout_milliseconds: Optional[Any] = None,
        server_name_overwrite: Optional[Any] = None,
        local_address: Optional[Any] = None,
        request_host_override: Optional[Any] = None,
        pseudo_header_order: Optional[Any] = None,
        h3_pseudo_header_order: Optional[Any] = None,
        default_headers: Optional[Any] = None,
        connect_headers: Optional[Any] = None,
        certificate_pinning_hosts: Optional[Any] = None,
        with_default_bad_pin_handler: Optional[Any] = None,
        request_cookies: Optional[Any] = None,
        custom_tls_client: Optional[Any] = None,
        client_certificates: Optional[Any] = None,
        max_idle_connections: Optional[Any] = None,
        max_idle_connections_per_host: Optional[Any] = None,
        max_connections_per_host: Optional[Any] = None,
        disable_keep_alives: Optional[Any] = None,
        disable_compression: Optional[Any] = None,
        idle_conn_timeout_seconds: Optional[Any] = None,
        max_response_header_bytes: Optional[Any] = None,
        write_buffer_size: Optional[Any] = None,
        read_buffer_size: Optional[Any] = None,
        disable_ipv4: Optional[Any] = None,
        disable_ipv6: Optional[Any] = None,
        tcp_ttl: Optional[Any] = None,
        tcp_window_size: Optional[Any] = None,
        tcp_window_scale: Optional[Any] = None,
        tcp_mss: Optional[Any] = None,
        allow_empty_cookies: Optional[Any] = None,
        without_cookie_jar: Optional[Any] = None,
        catch_panics: Optional[Any] = None,
        with_debug: Optional[Any] = None,
        disable_session_tickets: Optional[Any] = None,
        tls_keylog_path: Optional[Any] = None,
        root_ca_pem: Optional[Any] = None,
        h2_max_data_frame_size: Optional[Any] = None,
        preface_ping_idle_ms: Optional[Any] = None,
        hpack_indexing_policy: Optional[Any] = None,
        cookie_crumb: Optional[Any] = None,
        extension_permute_mode: Optional[Any] = None,
        extension_permute_prefix: Optional[Any] = None,
        h2_disable_priority_frames: Optional[Any] = None,
        header_order_by_dest: Optional[Any] = None,
        header_order_dest: Optional[Any] = None,
        tcp_dont_fragment: Optional[Any] = None,
        tcp_tos: Optional[Any] = None,
        tcp_no_delay: Optional[Any] = None,
        tcp_window_clamp: Optional[Any] = None,
        tcp_ip_id_mode: Optional[Any] = None,
        header_order: Optional[Any] = None,
        **kwargs: Any,
    ) -> Any:
        """Construct a Request, prepare it and send it.

        Every requests argument is supported, plus every TLS override the
        engine understands; None means 'use the session value'.
        """
        return self._dispatch_request(
            method,
            url,
            params=params,
            data=body if body is not None else data,
            headers=headers,
            cookies=cookies,
            files=files,
            auth=auth,
            timeout=timeout,
            allow_redirects=allow_redirects,
            proxies=proxies,
            hooks=hooks,
            stream=stream,
            verify=verify,
            cert=cert,
            json=json,
            context=context,
            tls_options=collect_tls_options(locals()),
            extra_kwargs=kwargs,
        )

    def get(
        self,
        url: Any,
        params: Optional[Any] = None,
        headers: Optional[Any] = None,
        cookies: Optional[Any] = None,
        files: Optional[Any] = None,
        auth: Optional[Any] = None,
        timeout: Optional[Any] = None,
        allow_redirects: Optional[Any] = None,
        proxies: Optional[Any] = None,
        hooks: Optional[Any] = None,
        stream: Optional[Any] = None,
        verify: Optional[Any] = None,
        cert: Optional[Any] = None,
        json: Optional[Any] = None,
        context: Optional[Any] = None,
        *,
        client_identifier: Optional[Any] = None,
        force_http1: Optional[Any] = None,
        disable_http3: Optional[Any] = None,
        with_protocol_racing: Optional[Any] = None,
        random_tls_extension_order: Optional[Any] = None,
        timeout_milliseconds: Optional[Any] = None,
        server_name_overwrite: Optional[Any] = None,
        local_address: Optional[Any] = None,
        request_host_override: Optional[Any] = None,
        pseudo_header_order: Optional[Any] = None,
        h3_pseudo_header_order: Optional[Any] = None,
        default_headers: Optional[Any] = None,
        connect_headers: Optional[Any] = None,
        certificate_pinning_hosts: Optional[Any] = None,
        with_default_bad_pin_handler: Optional[Any] = None,
        request_cookies: Optional[Any] = None,
        custom_tls_client: Optional[Any] = None,
        client_certificates: Optional[Any] = None,
        max_idle_connections: Optional[Any] = None,
        max_idle_connections_per_host: Optional[Any] = None,
        max_connections_per_host: Optional[Any] = None,
        disable_keep_alives: Optional[Any] = None,
        disable_compression: Optional[Any] = None,
        idle_conn_timeout_seconds: Optional[Any] = None,
        max_response_header_bytes: Optional[Any] = None,
        write_buffer_size: Optional[Any] = None,
        read_buffer_size: Optional[Any] = None,
        disable_ipv4: Optional[Any] = None,
        disable_ipv6: Optional[Any] = None,
        tcp_ttl: Optional[Any] = None,
        tcp_window_size: Optional[Any] = None,
        tcp_window_scale: Optional[Any] = None,
        tcp_mss: Optional[Any] = None,
        allow_empty_cookies: Optional[Any] = None,
        without_cookie_jar: Optional[Any] = None,
        catch_panics: Optional[Any] = None,
        with_debug: Optional[Any] = None,
        disable_session_tickets: Optional[Any] = None,
        tls_keylog_path: Optional[Any] = None,
        root_ca_pem: Optional[Any] = None,
        h2_max_data_frame_size: Optional[Any] = None,
        preface_ping_idle_ms: Optional[Any] = None,
        hpack_indexing_policy: Optional[Any] = None,
        cookie_crumb: Optional[Any] = None,
        extension_permute_mode: Optional[Any] = None,
        extension_permute_prefix: Optional[Any] = None,
        h2_disable_priority_frames: Optional[Any] = None,
        header_order_by_dest: Optional[Any] = None,
        header_order_dest: Optional[Any] = None,
        tcp_dont_fragment: Optional[Any] = None,
        tcp_tos: Optional[Any] = None,
        tcp_no_delay: Optional[Any] = None,
        tcp_window_clamp: Optional[Any] = None,
        tcp_ip_id_mode: Optional[Any] = None,
        header_order: Optional[Any] = None,
        **kwargs: Any,
    ) -> Any:
        """Send an HTTP GET request through this session."""
        return self.request(
            "GET",
            url,
            params=params,
            headers=headers,
            cookies=cookies,
            files=files,
            auth=auth,
            timeout=timeout,
            allow_redirects=allow_redirects,
            proxies=proxies,
            hooks=hooks,
            stream=stream,
            verify=verify,
            cert=cert,
            json=json,
            context=context,
            client_identifier=client_identifier,
            force_http1=force_http1,
            disable_http3=disable_http3,
            with_protocol_racing=with_protocol_racing,
            random_tls_extension_order=random_tls_extension_order,
            timeout_milliseconds=timeout_milliseconds,
            server_name_overwrite=server_name_overwrite,
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
            tcp_ttl=tcp_ttl,
            tcp_window_size=tcp_window_size,
            tcp_window_scale=tcp_window_scale,
            tcp_mss=tcp_mss,
            allow_empty_cookies=allow_empty_cookies,
            without_cookie_jar=without_cookie_jar,
            catch_panics=catch_panics,
            with_debug=with_debug,
            disable_session_tickets=disable_session_tickets,
            tls_keylog_path=tls_keylog_path,
            root_ca_pem=root_ca_pem,
            h2_max_data_frame_size=h2_max_data_frame_size,
            preface_ping_idle_ms=preface_ping_idle_ms,
            hpack_indexing_policy=hpack_indexing_policy,
            cookie_crumb=cookie_crumb,
            extension_permute_mode=extension_permute_mode,
            extension_permute_prefix=extension_permute_prefix,
            h2_disable_priority_frames=h2_disable_priority_frames,
            header_order_by_dest=header_order_by_dest,
            header_order_dest=header_order_dest,
            tcp_dont_fragment=tcp_dont_fragment,
            tcp_tos=tcp_tos,
            tcp_no_delay=tcp_no_delay,
            tcp_window_clamp=tcp_window_clamp,
            tcp_ip_id_mode=tcp_ip_id_mode,
            header_order=header_order,
            **kwargs,
        )

    def options(
        self,
        url: Any,
        params: Optional[Any] = None,
        data: Optional[Any] = None,
        headers: Optional[Any] = None,
        cookies: Optional[Any] = None,
        files: Optional[Any] = None,
        auth: Optional[Any] = None,
        timeout: Optional[Any] = None,
        allow_redirects: Optional[Any] = None,
        proxies: Optional[Any] = None,
        hooks: Optional[Any] = None,
        stream: Optional[Any] = None,
        verify: Optional[Any] = None,
        cert: Optional[Any] = None,
        json: Optional[Any] = None,
        context: Optional[Any] = None,
        *,
        client_identifier: Optional[Any] = None,
        force_http1: Optional[Any] = None,
        disable_http3: Optional[Any] = None,
        with_protocol_racing: Optional[Any] = None,
        random_tls_extension_order: Optional[Any] = None,
        timeout_milliseconds: Optional[Any] = None,
        server_name_overwrite: Optional[Any] = None,
        local_address: Optional[Any] = None,
        request_host_override: Optional[Any] = None,
        pseudo_header_order: Optional[Any] = None,
        h3_pseudo_header_order: Optional[Any] = None,
        default_headers: Optional[Any] = None,
        connect_headers: Optional[Any] = None,
        certificate_pinning_hosts: Optional[Any] = None,
        with_default_bad_pin_handler: Optional[Any] = None,
        request_cookies: Optional[Any] = None,
        custom_tls_client: Optional[Any] = None,
        client_certificates: Optional[Any] = None,
        max_idle_connections: Optional[Any] = None,
        max_idle_connections_per_host: Optional[Any] = None,
        max_connections_per_host: Optional[Any] = None,
        disable_keep_alives: Optional[Any] = None,
        disable_compression: Optional[Any] = None,
        idle_conn_timeout_seconds: Optional[Any] = None,
        max_response_header_bytes: Optional[Any] = None,
        write_buffer_size: Optional[Any] = None,
        read_buffer_size: Optional[Any] = None,
        disable_ipv4: Optional[Any] = None,
        disable_ipv6: Optional[Any] = None,
        tcp_ttl: Optional[Any] = None,
        tcp_window_size: Optional[Any] = None,
        tcp_window_scale: Optional[Any] = None,
        tcp_mss: Optional[Any] = None,
        allow_empty_cookies: Optional[Any] = None,
        without_cookie_jar: Optional[Any] = None,
        catch_panics: Optional[Any] = None,
        with_debug: Optional[Any] = None,
        disable_session_tickets: Optional[Any] = None,
        tls_keylog_path: Optional[Any] = None,
        root_ca_pem: Optional[Any] = None,
        h2_max_data_frame_size: Optional[Any] = None,
        preface_ping_idle_ms: Optional[Any] = None,
        hpack_indexing_policy: Optional[Any] = None,
        cookie_crumb: Optional[Any] = None,
        extension_permute_mode: Optional[Any] = None,
        extension_permute_prefix: Optional[Any] = None,
        h2_disable_priority_frames: Optional[Any] = None,
        header_order_by_dest: Optional[Any] = None,
        header_order_dest: Optional[Any] = None,
        tcp_dont_fragment: Optional[Any] = None,
        tcp_tos: Optional[Any] = None,
        tcp_no_delay: Optional[Any] = None,
        tcp_window_clamp: Optional[Any] = None,
        tcp_ip_id_mode: Optional[Any] = None,
        header_order: Optional[Any] = None,
        **kwargs: Any,
    ) -> Any:
        """Send an HTTP OPTIONS request through this session."""
        return self.request(
            "OPTIONS",
            url,
            params=params,
            data=data,
            headers=headers,
            cookies=cookies,
            files=files,
            auth=auth,
            timeout=timeout,
            allow_redirects=allow_redirects,
            proxies=proxies,
            hooks=hooks,
            stream=stream,
            verify=verify,
            cert=cert,
            json=json,
            context=context,
            client_identifier=client_identifier,
            force_http1=force_http1,
            disable_http3=disable_http3,
            with_protocol_racing=with_protocol_racing,
            random_tls_extension_order=random_tls_extension_order,
            timeout_milliseconds=timeout_milliseconds,
            server_name_overwrite=server_name_overwrite,
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
            tcp_ttl=tcp_ttl,
            tcp_window_size=tcp_window_size,
            tcp_window_scale=tcp_window_scale,
            tcp_mss=tcp_mss,
            allow_empty_cookies=allow_empty_cookies,
            without_cookie_jar=without_cookie_jar,
            catch_panics=catch_panics,
            with_debug=with_debug,
            disable_session_tickets=disable_session_tickets,
            tls_keylog_path=tls_keylog_path,
            root_ca_pem=root_ca_pem,
            h2_max_data_frame_size=h2_max_data_frame_size,
            preface_ping_idle_ms=preface_ping_idle_ms,
            hpack_indexing_policy=hpack_indexing_policy,
            cookie_crumb=cookie_crumb,
            extension_permute_mode=extension_permute_mode,
            extension_permute_prefix=extension_permute_prefix,
            h2_disable_priority_frames=h2_disable_priority_frames,
            header_order_by_dest=header_order_by_dest,
            header_order_dest=header_order_dest,
            tcp_dont_fragment=tcp_dont_fragment,
            tcp_tos=tcp_tos,
            tcp_no_delay=tcp_no_delay,
            tcp_window_clamp=tcp_window_clamp,
            tcp_ip_id_mode=tcp_ip_id_mode,
            header_order=header_order,
            **kwargs,
        )

    def head(
        self,
        url: Any,
        allow_redirects: Optional[bool] = False,
        params: Optional[Any] = None,
        data: Optional[Any] = None,
        headers: Optional[Any] = None,
        cookies: Optional[Any] = None,
        files: Optional[Any] = None,
        auth: Optional[Any] = None,
        timeout: Optional[Any] = None,
        proxies: Optional[Any] = None,
        hooks: Optional[Any] = None,
        stream: Optional[Any] = None,
        verify: Optional[Any] = None,
        cert: Optional[Any] = None,
        json: Optional[Any] = None,
        context: Optional[Any] = None,
        *,
        client_identifier: Optional[Any] = None,
        force_http1: Optional[Any] = None,
        disable_http3: Optional[Any] = None,
        with_protocol_racing: Optional[Any] = None,
        random_tls_extension_order: Optional[Any] = None,
        timeout_milliseconds: Optional[Any] = None,
        server_name_overwrite: Optional[Any] = None,
        local_address: Optional[Any] = None,
        request_host_override: Optional[Any] = None,
        pseudo_header_order: Optional[Any] = None,
        h3_pseudo_header_order: Optional[Any] = None,
        default_headers: Optional[Any] = None,
        connect_headers: Optional[Any] = None,
        certificate_pinning_hosts: Optional[Any] = None,
        with_default_bad_pin_handler: Optional[Any] = None,
        request_cookies: Optional[Any] = None,
        custom_tls_client: Optional[Any] = None,
        client_certificates: Optional[Any] = None,
        max_idle_connections: Optional[Any] = None,
        max_idle_connections_per_host: Optional[Any] = None,
        max_connections_per_host: Optional[Any] = None,
        disable_keep_alives: Optional[Any] = None,
        disable_compression: Optional[Any] = None,
        idle_conn_timeout_seconds: Optional[Any] = None,
        max_response_header_bytes: Optional[Any] = None,
        write_buffer_size: Optional[Any] = None,
        read_buffer_size: Optional[Any] = None,
        disable_ipv4: Optional[Any] = None,
        disable_ipv6: Optional[Any] = None,
        tcp_ttl: Optional[Any] = None,
        tcp_window_size: Optional[Any] = None,
        tcp_window_scale: Optional[Any] = None,
        tcp_mss: Optional[Any] = None,
        allow_empty_cookies: Optional[Any] = None,
        without_cookie_jar: Optional[Any] = None,
        catch_panics: Optional[Any] = None,
        with_debug: Optional[Any] = None,
        disable_session_tickets: Optional[Any] = None,
        tls_keylog_path: Optional[Any] = None,
        root_ca_pem: Optional[Any] = None,
        h2_max_data_frame_size: Optional[Any] = None,
        preface_ping_idle_ms: Optional[Any] = None,
        hpack_indexing_policy: Optional[Any] = None,
        cookie_crumb: Optional[Any] = None,
        extension_permute_mode: Optional[Any] = None,
        extension_permute_prefix: Optional[Any] = None,
        h2_disable_priority_frames: Optional[Any] = None,
        header_order_by_dest: Optional[Any] = None,
        header_order_dest: Optional[Any] = None,
        tcp_dont_fragment: Optional[Any] = None,
        tcp_tos: Optional[Any] = None,
        tcp_no_delay: Optional[Any] = None,
        tcp_window_clamp: Optional[Any] = None,
        tcp_ip_id_mode: Optional[Any] = None,
        header_order: Optional[Any] = None,
        **kwargs: Any,
    ) -> Any:
        """Send an HTTP HEAD request through this session."""
        return self.request(
            "HEAD",
            url,
            params=params,
            data=data,
            headers=headers,
            cookies=cookies,
            files=files,
            auth=auth,
            timeout=timeout,
            allow_redirects=allow_redirects,
            proxies=proxies,
            hooks=hooks,
            stream=stream,
            verify=verify,
            cert=cert,
            json=json,
            context=context,
            client_identifier=client_identifier,
            force_http1=force_http1,
            disable_http3=disable_http3,
            with_protocol_racing=with_protocol_racing,
            random_tls_extension_order=random_tls_extension_order,
            timeout_milliseconds=timeout_milliseconds,
            server_name_overwrite=server_name_overwrite,
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
            tcp_ttl=tcp_ttl,
            tcp_window_size=tcp_window_size,
            tcp_window_scale=tcp_window_scale,
            tcp_mss=tcp_mss,
            allow_empty_cookies=allow_empty_cookies,
            without_cookie_jar=without_cookie_jar,
            catch_panics=catch_panics,
            with_debug=with_debug,
            disable_session_tickets=disable_session_tickets,
            tls_keylog_path=tls_keylog_path,
            root_ca_pem=root_ca_pem,
            h2_max_data_frame_size=h2_max_data_frame_size,
            preface_ping_idle_ms=preface_ping_idle_ms,
            hpack_indexing_policy=hpack_indexing_policy,
            cookie_crumb=cookie_crumb,
            extension_permute_mode=extension_permute_mode,
            extension_permute_prefix=extension_permute_prefix,
            h2_disable_priority_frames=h2_disable_priority_frames,
            header_order_by_dest=header_order_by_dest,
            header_order_dest=header_order_dest,
            tcp_dont_fragment=tcp_dont_fragment,
            tcp_tos=tcp_tos,
            tcp_no_delay=tcp_no_delay,
            tcp_window_clamp=tcp_window_clamp,
            tcp_ip_id_mode=tcp_ip_id_mode,
            header_order=header_order,
            **kwargs,
        )

    def post(
        self,
        url: Any,
        data: Optional[Any] = None,
        json: Optional[Any] = None,
        headers: Optional[Any] = None,
        cookies: Optional[Any] = None,
        files: Optional[Any] = None,
        auth: Optional[Any] = None,
        timeout: Optional[Any] = None,
        allow_redirects: Optional[Any] = None,
        proxies: Optional[Any] = None,
        hooks: Optional[Any] = None,
        stream: Optional[Any] = None,
        verify: Optional[Any] = None,
        cert: Optional[Any] = None,
        context: Optional[Any] = None,
        *,
        client_identifier: Optional[Any] = None,
        force_http1: Optional[Any] = None,
        disable_http3: Optional[Any] = None,
        with_protocol_racing: Optional[Any] = None,
        random_tls_extension_order: Optional[Any] = None,
        timeout_milliseconds: Optional[Any] = None,
        server_name_overwrite: Optional[Any] = None,
        local_address: Optional[Any] = None,
        request_host_override: Optional[Any] = None,
        pseudo_header_order: Optional[Any] = None,
        h3_pseudo_header_order: Optional[Any] = None,
        default_headers: Optional[Any] = None,
        connect_headers: Optional[Any] = None,
        certificate_pinning_hosts: Optional[Any] = None,
        with_default_bad_pin_handler: Optional[Any] = None,
        request_cookies: Optional[Any] = None,
        custom_tls_client: Optional[Any] = None,
        client_certificates: Optional[Any] = None,
        max_idle_connections: Optional[Any] = None,
        max_idle_connections_per_host: Optional[Any] = None,
        max_connections_per_host: Optional[Any] = None,
        disable_keep_alives: Optional[Any] = None,
        disable_compression: Optional[Any] = None,
        idle_conn_timeout_seconds: Optional[Any] = None,
        max_response_header_bytes: Optional[Any] = None,
        write_buffer_size: Optional[Any] = None,
        read_buffer_size: Optional[Any] = None,
        disable_ipv4: Optional[Any] = None,
        disable_ipv6: Optional[Any] = None,
        tcp_ttl: Optional[Any] = None,
        tcp_window_size: Optional[Any] = None,
        tcp_window_scale: Optional[Any] = None,
        tcp_mss: Optional[Any] = None,
        allow_empty_cookies: Optional[Any] = None,
        without_cookie_jar: Optional[Any] = None,
        catch_panics: Optional[Any] = None,
        with_debug: Optional[Any] = None,
        disable_session_tickets: Optional[Any] = None,
        tls_keylog_path: Optional[Any] = None,
        root_ca_pem: Optional[Any] = None,
        h2_max_data_frame_size: Optional[Any] = None,
        preface_ping_idle_ms: Optional[Any] = None,
        hpack_indexing_policy: Optional[Any] = None,
        cookie_crumb: Optional[Any] = None,
        extension_permute_mode: Optional[Any] = None,
        extension_permute_prefix: Optional[Any] = None,
        h2_disable_priority_frames: Optional[Any] = None,
        header_order_by_dest: Optional[Any] = None,
        header_order_dest: Optional[Any] = None,
        tcp_dont_fragment: Optional[Any] = None,
        tcp_tos: Optional[Any] = None,
        tcp_no_delay: Optional[Any] = None,
        tcp_window_clamp: Optional[Any] = None,
        tcp_ip_id_mode: Optional[Any] = None,
        header_order: Optional[Any] = None,
        **kwargs: Any,
    ) -> Any:
        """Send an HTTP POST request through this session."""
        return self.request(
            "POST",
            url,
            data=data,
            json=json,
            headers=headers,
            cookies=cookies,
            files=files,
            auth=auth,
            timeout=timeout,
            allow_redirects=allow_redirects,
            proxies=proxies,
            hooks=hooks,
            stream=stream,
            verify=verify,
            cert=cert,
            context=context,
            client_identifier=client_identifier,
            force_http1=force_http1,
            disable_http3=disable_http3,
            with_protocol_racing=with_protocol_racing,
            random_tls_extension_order=random_tls_extension_order,
            timeout_milliseconds=timeout_milliseconds,
            server_name_overwrite=server_name_overwrite,
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
            tcp_ttl=tcp_ttl,
            tcp_window_size=tcp_window_size,
            tcp_window_scale=tcp_window_scale,
            tcp_mss=tcp_mss,
            allow_empty_cookies=allow_empty_cookies,
            without_cookie_jar=without_cookie_jar,
            catch_panics=catch_panics,
            with_debug=with_debug,
            disable_session_tickets=disable_session_tickets,
            tls_keylog_path=tls_keylog_path,
            root_ca_pem=root_ca_pem,
            h2_max_data_frame_size=h2_max_data_frame_size,
            preface_ping_idle_ms=preface_ping_idle_ms,
            hpack_indexing_policy=hpack_indexing_policy,
            cookie_crumb=cookie_crumb,
            extension_permute_mode=extension_permute_mode,
            extension_permute_prefix=extension_permute_prefix,
            h2_disable_priority_frames=h2_disable_priority_frames,
            header_order_by_dest=header_order_by_dest,
            header_order_dest=header_order_dest,
            tcp_dont_fragment=tcp_dont_fragment,
            tcp_tos=tcp_tos,
            tcp_no_delay=tcp_no_delay,
            tcp_window_clamp=tcp_window_clamp,
            tcp_ip_id_mode=tcp_ip_id_mode,
            header_order=header_order,
            **kwargs,
        )

    def put(
        self,
        url: Any,
        data: Optional[Any] = None,
        headers: Optional[Any] = None,
        cookies: Optional[Any] = None,
        files: Optional[Any] = None,
        auth: Optional[Any] = None,
        timeout: Optional[Any] = None,
        allow_redirects: Optional[Any] = None,
        proxies: Optional[Any] = None,
        hooks: Optional[Any] = None,
        stream: Optional[Any] = None,
        verify: Optional[Any] = None,
        cert: Optional[Any] = None,
        context: Optional[Any] = None,
        *,
        client_identifier: Optional[Any] = None,
        force_http1: Optional[Any] = None,
        disable_http3: Optional[Any] = None,
        with_protocol_racing: Optional[Any] = None,
        random_tls_extension_order: Optional[Any] = None,
        timeout_milliseconds: Optional[Any] = None,
        server_name_overwrite: Optional[Any] = None,
        local_address: Optional[Any] = None,
        request_host_override: Optional[Any] = None,
        pseudo_header_order: Optional[Any] = None,
        h3_pseudo_header_order: Optional[Any] = None,
        default_headers: Optional[Any] = None,
        connect_headers: Optional[Any] = None,
        certificate_pinning_hosts: Optional[Any] = None,
        with_default_bad_pin_handler: Optional[Any] = None,
        request_cookies: Optional[Any] = None,
        custom_tls_client: Optional[Any] = None,
        client_certificates: Optional[Any] = None,
        max_idle_connections: Optional[Any] = None,
        max_idle_connections_per_host: Optional[Any] = None,
        max_connections_per_host: Optional[Any] = None,
        disable_keep_alives: Optional[Any] = None,
        disable_compression: Optional[Any] = None,
        idle_conn_timeout_seconds: Optional[Any] = None,
        max_response_header_bytes: Optional[Any] = None,
        write_buffer_size: Optional[Any] = None,
        read_buffer_size: Optional[Any] = None,
        disable_ipv4: Optional[Any] = None,
        disable_ipv6: Optional[Any] = None,
        tcp_ttl: Optional[Any] = None,
        tcp_window_size: Optional[Any] = None,
        tcp_window_scale: Optional[Any] = None,
        tcp_mss: Optional[Any] = None,
        allow_empty_cookies: Optional[Any] = None,
        without_cookie_jar: Optional[Any] = None,
        catch_panics: Optional[Any] = None,
        with_debug: Optional[Any] = None,
        disable_session_tickets: Optional[Any] = None,
        tls_keylog_path: Optional[Any] = None,
        root_ca_pem: Optional[Any] = None,
        h2_max_data_frame_size: Optional[Any] = None,
        preface_ping_idle_ms: Optional[Any] = None,
        hpack_indexing_policy: Optional[Any] = None,
        cookie_crumb: Optional[Any] = None,
        extension_permute_mode: Optional[Any] = None,
        extension_permute_prefix: Optional[Any] = None,
        h2_disable_priority_frames: Optional[Any] = None,
        header_order_by_dest: Optional[Any] = None,
        header_order_dest: Optional[Any] = None,
        tcp_dont_fragment: Optional[Any] = None,
        tcp_tos: Optional[Any] = None,
        tcp_no_delay: Optional[Any] = None,
        tcp_window_clamp: Optional[Any] = None,
        tcp_ip_id_mode: Optional[Any] = None,
        header_order: Optional[Any] = None,
        **kwargs: Any,
    ) -> Any:
        """Send an HTTP PUT request through this session."""
        return self.request(
            "PUT",
            url,
            data=data,
            headers=headers,
            cookies=cookies,
            files=files,
            auth=auth,
            timeout=timeout,
            allow_redirects=allow_redirects,
            proxies=proxies,
            hooks=hooks,
            stream=stream,
            verify=verify,
            cert=cert,
            context=context,
            client_identifier=client_identifier,
            force_http1=force_http1,
            disable_http3=disable_http3,
            with_protocol_racing=with_protocol_racing,
            random_tls_extension_order=random_tls_extension_order,
            timeout_milliseconds=timeout_milliseconds,
            server_name_overwrite=server_name_overwrite,
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
            tcp_ttl=tcp_ttl,
            tcp_window_size=tcp_window_size,
            tcp_window_scale=tcp_window_scale,
            tcp_mss=tcp_mss,
            allow_empty_cookies=allow_empty_cookies,
            without_cookie_jar=without_cookie_jar,
            catch_panics=catch_panics,
            with_debug=with_debug,
            disable_session_tickets=disable_session_tickets,
            tls_keylog_path=tls_keylog_path,
            root_ca_pem=root_ca_pem,
            h2_max_data_frame_size=h2_max_data_frame_size,
            preface_ping_idle_ms=preface_ping_idle_ms,
            hpack_indexing_policy=hpack_indexing_policy,
            cookie_crumb=cookie_crumb,
            extension_permute_mode=extension_permute_mode,
            extension_permute_prefix=extension_permute_prefix,
            h2_disable_priority_frames=h2_disable_priority_frames,
            header_order_by_dest=header_order_by_dest,
            header_order_dest=header_order_dest,
            tcp_dont_fragment=tcp_dont_fragment,
            tcp_tos=tcp_tos,
            tcp_no_delay=tcp_no_delay,
            tcp_window_clamp=tcp_window_clamp,
            tcp_ip_id_mode=tcp_ip_id_mode,
            header_order=header_order,
            **kwargs,
        )

    def patch(
        self,
        url: Any,
        data: Optional[Any] = None,
        headers: Optional[Any] = None,
        cookies: Optional[Any] = None,
        files: Optional[Any] = None,
        auth: Optional[Any] = None,
        timeout: Optional[Any] = None,
        allow_redirects: Optional[Any] = None,
        proxies: Optional[Any] = None,
        hooks: Optional[Any] = None,
        stream: Optional[Any] = None,
        verify: Optional[Any] = None,
        cert: Optional[Any] = None,
        context: Optional[Any] = None,
        *,
        client_identifier: Optional[Any] = None,
        force_http1: Optional[Any] = None,
        disable_http3: Optional[Any] = None,
        with_protocol_racing: Optional[Any] = None,
        random_tls_extension_order: Optional[Any] = None,
        timeout_milliseconds: Optional[Any] = None,
        server_name_overwrite: Optional[Any] = None,
        local_address: Optional[Any] = None,
        request_host_override: Optional[Any] = None,
        pseudo_header_order: Optional[Any] = None,
        h3_pseudo_header_order: Optional[Any] = None,
        default_headers: Optional[Any] = None,
        connect_headers: Optional[Any] = None,
        certificate_pinning_hosts: Optional[Any] = None,
        with_default_bad_pin_handler: Optional[Any] = None,
        request_cookies: Optional[Any] = None,
        custom_tls_client: Optional[Any] = None,
        client_certificates: Optional[Any] = None,
        max_idle_connections: Optional[Any] = None,
        max_idle_connections_per_host: Optional[Any] = None,
        max_connections_per_host: Optional[Any] = None,
        disable_keep_alives: Optional[Any] = None,
        disable_compression: Optional[Any] = None,
        idle_conn_timeout_seconds: Optional[Any] = None,
        max_response_header_bytes: Optional[Any] = None,
        write_buffer_size: Optional[Any] = None,
        read_buffer_size: Optional[Any] = None,
        disable_ipv4: Optional[Any] = None,
        disable_ipv6: Optional[Any] = None,
        tcp_ttl: Optional[Any] = None,
        tcp_window_size: Optional[Any] = None,
        tcp_window_scale: Optional[Any] = None,
        tcp_mss: Optional[Any] = None,
        allow_empty_cookies: Optional[Any] = None,
        without_cookie_jar: Optional[Any] = None,
        catch_panics: Optional[Any] = None,
        with_debug: Optional[Any] = None,
        disable_session_tickets: Optional[Any] = None,
        tls_keylog_path: Optional[Any] = None,
        root_ca_pem: Optional[Any] = None,
        h2_max_data_frame_size: Optional[Any] = None,
        preface_ping_idle_ms: Optional[Any] = None,
        hpack_indexing_policy: Optional[Any] = None,
        cookie_crumb: Optional[Any] = None,
        extension_permute_mode: Optional[Any] = None,
        extension_permute_prefix: Optional[Any] = None,
        h2_disable_priority_frames: Optional[Any] = None,
        header_order_by_dest: Optional[Any] = None,
        header_order_dest: Optional[Any] = None,
        tcp_dont_fragment: Optional[Any] = None,
        tcp_tos: Optional[Any] = None,
        tcp_no_delay: Optional[Any] = None,
        tcp_window_clamp: Optional[Any] = None,
        tcp_ip_id_mode: Optional[Any] = None,
        header_order: Optional[Any] = None,
        **kwargs: Any,
    ) -> Any:
        """Send an HTTP PATCH request through this session."""
        return self.request(
            "PATCH",
            url,
            data=data,
            headers=headers,
            cookies=cookies,
            files=files,
            auth=auth,
            timeout=timeout,
            allow_redirects=allow_redirects,
            proxies=proxies,
            hooks=hooks,
            stream=stream,
            verify=verify,
            cert=cert,
            context=context,
            client_identifier=client_identifier,
            force_http1=force_http1,
            disable_http3=disable_http3,
            with_protocol_racing=with_protocol_racing,
            random_tls_extension_order=random_tls_extension_order,
            timeout_milliseconds=timeout_milliseconds,
            server_name_overwrite=server_name_overwrite,
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
            tcp_ttl=tcp_ttl,
            tcp_window_size=tcp_window_size,
            tcp_window_scale=tcp_window_scale,
            tcp_mss=tcp_mss,
            allow_empty_cookies=allow_empty_cookies,
            without_cookie_jar=without_cookie_jar,
            catch_panics=catch_panics,
            with_debug=with_debug,
            disable_session_tickets=disable_session_tickets,
            tls_keylog_path=tls_keylog_path,
            root_ca_pem=root_ca_pem,
            h2_max_data_frame_size=h2_max_data_frame_size,
            preface_ping_idle_ms=preface_ping_idle_ms,
            hpack_indexing_policy=hpack_indexing_policy,
            cookie_crumb=cookie_crumb,
            extension_permute_mode=extension_permute_mode,
            extension_permute_prefix=extension_permute_prefix,
            h2_disable_priority_frames=h2_disable_priority_frames,
            header_order_by_dest=header_order_by_dest,
            header_order_dest=header_order_dest,
            tcp_dont_fragment=tcp_dont_fragment,
            tcp_tos=tcp_tos,
            tcp_no_delay=tcp_no_delay,
            tcp_window_clamp=tcp_window_clamp,
            tcp_ip_id_mode=tcp_ip_id_mode,
            header_order=header_order,
            **kwargs,
        )

    def delete(
        self,
        url: Any,
        params: Optional[Any] = None,
        data: Optional[Any] = None,
        headers: Optional[Any] = None,
        cookies: Optional[Any] = None,
        files: Optional[Any] = None,
        auth: Optional[Any] = None,
        timeout: Optional[Any] = None,
        allow_redirects: Optional[Any] = None,
        proxies: Optional[Any] = None,
        hooks: Optional[Any] = None,
        stream: Optional[Any] = None,
        verify: Optional[Any] = None,
        cert: Optional[Any] = None,
        json: Optional[Any] = None,
        context: Optional[Any] = None,
        *,
        client_identifier: Optional[Any] = None,
        force_http1: Optional[Any] = None,
        disable_http3: Optional[Any] = None,
        with_protocol_racing: Optional[Any] = None,
        random_tls_extension_order: Optional[Any] = None,
        timeout_milliseconds: Optional[Any] = None,
        server_name_overwrite: Optional[Any] = None,
        local_address: Optional[Any] = None,
        request_host_override: Optional[Any] = None,
        pseudo_header_order: Optional[Any] = None,
        h3_pseudo_header_order: Optional[Any] = None,
        default_headers: Optional[Any] = None,
        connect_headers: Optional[Any] = None,
        certificate_pinning_hosts: Optional[Any] = None,
        with_default_bad_pin_handler: Optional[Any] = None,
        request_cookies: Optional[Any] = None,
        custom_tls_client: Optional[Any] = None,
        client_certificates: Optional[Any] = None,
        max_idle_connections: Optional[Any] = None,
        max_idle_connections_per_host: Optional[Any] = None,
        max_connections_per_host: Optional[Any] = None,
        disable_keep_alives: Optional[Any] = None,
        disable_compression: Optional[Any] = None,
        idle_conn_timeout_seconds: Optional[Any] = None,
        max_response_header_bytes: Optional[Any] = None,
        write_buffer_size: Optional[Any] = None,
        read_buffer_size: Optional[Any] = None,
        disable_ipv4: Optional[Any] = None,
        disable_ipv6: Optional[Any] = None,
        tcp_ttl: Optional[Any] = None,
        tcp_window_size: Optional[Any] = None,
        tcp_window_scale: Optional[Any] = None,
        tcp_mss: Optional[Any] = None,
        allow_empty_cookies: Optional[Any] = None,
        without_cookie_jar: Optional[Any] = None,
        catch_panics: Optional[Any] = None,
        with_debug: Optional[Any] = None,
        disable_session_tickets: Optional[Any] = None,
        tls_keylog_path: Optional[Any] = None,
        root_ca_pem: Optional[Any] = None,
        h2_max_data_frame_size: Optional[Any] = None,
        preface_ping_idle_ms: Optional[Any] = None,
        hpack_indexing_policy: Optional[Any] = None,
        cookie_crumb: Optional[Any] = None,
        extension_permute_mode: Optional[Any] = None,
        extension_permute_prefix: Optional[Any] = None,
        h2_disable_priority_frames: Optional[Any] = None,
        header_order_by_dest: Optional[Any] = None,
        header_order_dest: Optional[Any] = None,
        tcp_dont_fragment: Optional[Any] = None,
        tcp_tos: Optional[Any] = None,
        tcp_no_delay: Optional[Any] = None,
        tcp_window_clamp: Optional[Any] = None,
        tcp_ip_id_mode: Optional[Any] = None,
        header_order: Optional[Any] = None,
        **kwargs: Any,
    ) -> Any:
        """Send an HTTP DELETE request through this session."""
        return self.request(
            "DELETE",
            url,
            params=params,
            data=data,
            headers=headers,
            cookies=cookies,
            files=files,
            auth=auth,
            timeout=timeout,
            allow_redirects=allow_redirects,
            proxies=proxies,
            hooks=hooks,
            stream=stream,
            verify=verify,
            cert=cert,
            json=json,
            context=context,
            client_identifier=client_identifier,
            force_http1=force_http1,
            disable_http3=disable_http3,
            with_protocol_racing=with_protocol_racing,
            random_tls_extension_order=random_tls_extension_order,
            timeout_milliseconds=timeout_milliseconds,
            server_name_overwrite=server_name_overwrite,
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
            tcp_ttl=tcp_ttl,
            tcp_window_size=tcp_window_size,
            tcp_window_scale=tcp_window_scale,
            tcp_mss=tcp_mss,
            allow_empty_cookies=allow_empty_cookies,
            without_cookie_jar=without_cookie_jar,
            catch_panics=catch_panics,
            with_debug=with_debug,
            disable_session_tickets=disable_session_tickets,
            tls_keylog_path=tls_keylog_path,
            root_ca_pem=root_ca_pem,
            h2_max_data_frame_size=h2_max_data_frame_size,
            preface_ping_idle_ms=preface_ping_idle_ms,
            hpack_indexing_policy=hpack_indexing_policy,
            cookie_crumb=cookie_crumb,
            extension_permute_mode=extension_permute_mode,
            extension_permute_prefix=extension_permute_prefix,
            h2_disable_priority_frames=h2_disable_priority_frames,
            header_order_by_dest=header_order_by_dest,
            header_order_dest=header_order_dest,
            tcp_dont_fragment=tcp_dont_fragment,
            tcp_tos=tcp_tos,
            tcp_no_delay=tcp_no_delay,
            tcp_window_clamp=tcp_window_clamp,
            tcp_ip_id_mode=tcp_ip_id_mode,
            header_order=header_order,
            **kwargs,
        )


__all__ = [
    "REQUESTS_OWNED_ATTRIBUTES",
    "SPECIAL_OPTION_NAMES",
    "TLS_REQUEST_OPTION_NAMES",
    "TLS_SESSION_OPTION_DEFAULTS",
    "TLS_SESSION_OPTION_NAMES",
    "TLSOptionsMixin",
    "TLSVerbMixin",
    "collect_tls_options",
]
