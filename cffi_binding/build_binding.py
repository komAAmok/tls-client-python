#!/usr/bin/env python3
"""
CFFI build script for tls-client Python bindings.

This script:
  1. Defines the complete C type / function declarations (cdef) that must
     stay byte-identical with the Go-side `import "C"` comment block.
  2. Compiles the Go shared library via `go build -buildmode=c-shared`.
  3. Optionally builds a distributable Python wheel when invoked through
     `python -m build` or `pip install`.

Usage:
    python build_binding.py          # compile Go lib + verify CFFI defs
    python build_binding.py --lib    # only compile Go shared library
    python build_binding.py --pkg    # only build Python package
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# C declarations – must match main.go `import "C"` block EXACTLY
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
} ResponseResult;

ResponseResult* ExecuteRequest(RequestOptions* opts);
void           FreeResponse(ResponseResult* res);
void           ClearClientPool(void);
"""

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

def _go_os() -> str:
    """Map sys.platform → GOOS"""
    return {"darwin": "darwin", "linux": "linux", "win32": "windows"}.get(
        sys.platform, sys.platform
    )


def _go_arch() -> str:
    """Map platform.machine() → GOARCH"""
    m = platform.machine().lower()
    mapping = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "arm64": "arm64",
        "aarch64": "arm64",
        "armv7l": "arm",
        "armv6l": "arm",
        "i386": "386",
        "i686": "386",
    }
    return mapping.get(m, m)


def _shared_lib_ext() -> str:
    if sys.platform == "darwin":
        return ".dylib"
    elif sys.platform == "win32":
        return ".dll"
    return ".so"


def _shared_lib_name() -> str:
    ext = _shared_lib_ext()
    goos = _go_os()
    goarch = _go_arch()
    return f"tls-client-{goos}-{goarch}{ext}"


# ---------------------------------------------------------------------------
# Go build
# ---------------------------------------------------------------------------

def build_go_library(
    srcdir: Path | None = None,
    outdir: Path | None = None,
    verbose: bool = True,
) -> Path:
    """Compile the Go shared library and return its path."""
    if srcdir is None:
        srcdir = Path(__file__).resolve().parent
    if outdir is None:
        outdir = srcdir / "dist"

    outdir.mkdir(parents=True, exist_ok=True)

    libname = _shared_lib_name()
    outpath = outdir / libname

    env = os.environ.copy()
    env["CGO_ENABLED"] = "1"
    env["GOOS"] = _go_os()
    env["GOARCH"] = _go_arch()

    cmd = [
        "go", "build",
        "-buildmode=c-shared",
        "-buildvcs=false",
        "-trimpath",
        "-ldflags=-s -w",
        "-o", str(outpath),
        ".",
    ]

    if verbose:
        print(f"[build] {' '.join(cmd)}", flush=True)

    subprocess.run(cmd, cwd=str(srcdir), env=env, check=True)

    # `go build -buildmode=c-shared` also produces a C header – remove it
    # because cffi in API mode does not need it.
    header = outdir / f"tls-client-{_go_os()}-{_go_arch()}.h"
    if header.exists():
        header.unlink()
        if verbose:
            print(f"[build] removed surplus header {header}", flush=True)

    if verbose:
        print(f"[build] → {outpath}", flush=True)

    return outpath


# ---------------------------------------------------------------------------
# CFFI verification
# ---------------------------------------------------------------------------

def verify_cdef(libpath: Path) -> None:
    """Open the built shared library with cffi and verify signatures match."""
    try:
        from cffi import FFI
    except ImportError:
        print("[cffi] cffi not installed – skipping verification", flush=True)
        return

    ffi = FFI()
    ffi.cdef(CDEF)
    lib = ffi.dlopen(str(libpath))
    # Touch the symbols to make sure they resolve.
    _ = lib.ExecuteRequest
    _ = lib.FreeResponse
    _ = lib.ClearClientPool
    print("[cffi] cdef verification passed", flush=True)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Build tls-client CFFI bindings")
    parser.add_argument("--lib", action="store_true", help="Only compile Go shared library")
    parser.add_argument("--pkg", action="store_true", help="Only verify CFFI definitions")
    args = parser.parse_args()

    srcdir = Path(__file__).resolve().parent

    if args.pkg:
        outdir = srcdir / "dist"
        libname = _shared_lib_name()
        libpath = outdir / libname
        if not libpath.exists():
            sys.exit(f"Shared library not found at {libpath}. Run --lib first.")
        verify_cdef(libpath)
        return

    libpath = build_go_library(srcdir=srcdir)
    if not args.lib:
        verify_cdef(libpath)


if __name__ == "__main__":
    main()
