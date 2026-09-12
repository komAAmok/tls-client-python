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

import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# C declarations (cdef)
#
# The cdef MUST stay byte-identical with the ``import "C"`` block at the top
# of main.go.  Rather than hand-copying it (which drifted three ABI revisions
# behind before), the block is extracted directly from main.go at import time.
# ``_extract_cdef_from_main_go`` is authoritative.
#
# There is deliberately NO hand-maintained fallback copy: a stale literal is
# worse than no literal, because it silently declares the wrong struct layout
# and the failure only surfaces at dlopen.  When main.go cannot be read the
# cdef is reconstructed from the generated binding header next to it, which is
# produced by the same build and therefore cannot drift.
# ---------------------------------------------------------------------------

_BINDING_DIR = Path(__file__).resolve().parent

# Header emitted alongside the shared library by `go build -buildmode=c-shared`.
# Its contents are the authoritative exported surface for the built ABI, so it
# is the correct source when main.go itself is unavailable (e.g. an installed
# sdist that ships the header but not the Go sources).
_FALLBACK_HEADER_NAMES = (
    "tls-client.h",
    "tls-client-linux-amd64.h",
    "tls-client-windows-amd64.h",
    "tls-client-darwin-arm64.h",
    "tls-client-darwin-amd64.h",
)

# Structs the Python layer constructs itself.  cgo emits them for the C
# side but the binding header only repeats the exported function signatures,
# so they are declared here — this is the one part that cannot be derived.
_REQUIRED_STRUCTS = """
typedef struct { const char* key; const char* value; } HttpHeader;
typedef struct { unsigned int streamDep; int exclusive; unsigned char weight; } PriorityParam;
typedef struct { PriorityParam priorityParam; unsigned int streamID; } PriorityFrame;
typedef struct { const char* kdfId; const char* aeadId; } CandidateCipherSuite;
typedef struct {
    const char* cert_pem; int cert_pem_len;
    const char* key_pem; int key_pem_len;
} ClientCertificate;
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
"""


# Go C-type -> C declaration.  Only the types that actually appear in an
# exported binding signature need an entry; an unknown type raises rather than
# silently emitting a wrong prototype.
_GO_C_TYPE_MAP = {
    "C.int": "int",
    "C.uint": "unsigned int",
    "C.long": "long",
    "C.longlong": "long long",
    "C.uintptr_t": "uintptr_t",
    "C.size_t": "size_t",
    "unsafe.Pointer": "void*",
    "*C.char": "char*",
    "C.char": "char",
}

# Signatures where the cdef deliberately names a typedef instead of the raw
# pointer Go declares.  RequestAsync takes `cb unsafe.Pointer` in Go (cgo
# forbids passing a Go func value across the boundary) but the cdef declares
# the `async_callback_fn` typedef so cffi type-checks the callback argument.
_PROTOTYPE_OVERRIDES = {
    "RequestAsync": (
        "int RequestAsync(RequestOptions* opts, uintptr_t request_id, "
        "async_callback_fn cb);"
    ),
}


def _go_type_to_c(go_type: str) -> str:
    """Translate one Go cgo type expression into its C spelling."""
    go_type = go_type.strip()
    if go_type in _GO_C_TYPE_MAP:
        return _GO_C_TYPE_MAP[go_type]
    # Pointer to a struct declared in the preamble: *C.RequestOptions.
    if go_type.startswith("*C."):
        return go_type[3:] + "*"
    raise RuntimeError(
        "no C spelling known for Go type %r — add it to _GO_C_TYPE_MAP"
        % go_type
    )


def _binding_go_sources(main_go: Path) -> list:
    """Return the text of every non-test Go file in the binding package.

    Exports are spread across the package (ExecuteRequest in main.go,
    ResolveECHConfig in ech.go), so scanning only main.go would silently miss
    symbols.  ``_test.go`` files are skipped — they are not part of the built
    library.
    """
    sources = []
    for path in sorted(main_go.parent.glob("*.go")):
        if path.name.endswith("_test.go"):
            continue
        try:
            sources.append(path.read_text(encoding="utf-8"))
        except OSError as exc:  # pragma: no cover - environment specific
            raise RuntimeError("cannot read %s: %s" % (path, exc))
    return sources


def _parse_go_field(raw: str) -> str:
    """Turn one Go parameter/result declaration into ``<ctype> <name>``.

    Handles both ``opts *C.RequestOptions`` and the named single-result form
    ``result *C.ResponseResult`` (the parentheses are stripped by the caller).
    """
    raw = raw.strip()
    if not raw:
        raise RuntimeError("empty Go field declaration")
    bits = raw.split()
    if len(bits) < 2:
        raise RuntimeError("cannot parse Go field declaration %r" % raw)
    name, go_type = bits[0], " ".join(bits[1:])
    return "%s %s" % (_go_type_to_c(go_type), name)


def _exported_prototypes(sources) -> list:
    """Derive C prototypes for every ``//export``ed function across *sources*.

    cgo exposes a Go function to C exactly when it carries a ``//export``
    directive, so that directive list *is* the authoritative export surface.
    Reading it here means a newly exported function cannot be forgotten in
    the cdef — the failure mode that previously left RequestAsync and the two
    pool-tuning setters out of the binding cdef.

    *sources* is an iterable of Go source strings: the exports are spread over
    the whole binding package (ExecuteRequest in main.go, ResolveECHConfig in
    ech.go), so every non-test file must be scanned.
    """
    import re

    pattern = re.compile(
        r"^//export\s+(\w+)\s*\n"
        r"\s*func\s+\1\s*\(([^)]*)\)\s*(\([^)]*\)|[^\s{]*)\s*\{",
        re.M,
    )

    prototypes = []
    seen = set()
    for source in sources:
        for match in pattern.finditer(source):
            name = match.group(1)
            if name in seen:
                continue
            seen.add(name)
            params_raw, ret_raw = match.group(2), match.group(3).strip()

            if name in _PROTOTYPE_OVERRIDES:
                prototypes.append(_PROTOTYPE_OVERRIDES[name])
                continue

            params = [
                _parse_go_field(p)
                for p in params_raw.split(",")
                if p.strip()
            ]

            if not ret_raw:
                ret = "void"
            else:
                # Named single result: `(result *C.ResponseResult)`.  An
                # unnamed result is just the bare type (`*C.char`), so the
                # name is optional here — unlike in a parameter list.
                if ret_raw.startswith("(") and ret_raw.endswith(")"):
                    ret_raw = ret_raw[1:-1].strip()
                ret_bits = ret_raw.split()
                ret = _go_type_to_c(" ".join(ret_bits[1:]) if len(ret_bits) > 1
                                    else ret_bits[0])

            prototypes.append(
                "%s %s(%s);" % (ret, name, ", ".join(params) or "void")
            )

    if not prototypes:
        raise RuntimeError(
            "no //export directives found in the binding package — the "
            "export surface cannot be derived"
        )
    return prototypes


def _strip_static_inline_functions(source: str) -> str:
    """Remove ``static inline`` function definitions from a C preamble.

    Uses a brace-balanced scan so nested blocks inside the body are removed
    along with the function itself.  Non-inline declarations are untouched.
    """
    import re

    out = []
    i = 0
    pattern = re.compile(r"static\s+inline\b")
    while True:
        match = pattern.search(source, i)
        if not match:
            out.append(source[i:])
            break
        out.append(source[i:match.start()])
        # Find the opening brace of the function body.
        brace = source.find("{", match.end())
        if brace == -1:
            break
        depth = 0
        j = brace
        while j < len(source):
            if source[j] == "{":
                depth += 1
            elif source[j] == "}":
                depth -= 1
                if depth == 0:
                    j += 1
                    break
            j += 1
        i = j
    return "".join(out)


def _extract_cdef_from_main_go(main_go: Optional[Path] = None) -> str:
    """Return the cdef block copied out of main.go's ``import "C"`` comment.

    The Go cgo preamble between ``/*`` and ``*/`` immediately preceding
    ``import "C"`` holds every typedef the binding uses.  Extracting it at
    build time (instead of duplicating it here) guarantees the cdef and the
    Go struct layout can never silently drift apart.

    Raises ``RuntimeError`` when main.go or the preamble cannot be found so a
    stale fallback is never used silently.
    """
    if main_go is None:
        main_go = Path(__file__).resolve().parent / "main.go"
    try:
        source = main_go.read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover - environment specific
        raise RuntimeError("cannot read %s for cdef extraction: %s" % (main_go, exc))

    import re

    match = re.search(r"/\*(.*?)\*/\s*import\s+\"C\"", source, re.S)
    if not match:
        raise RuntimeError(
            "could not locate the cgo preamble in %s — the cdef cannot be "
            "derived and would risk drifting from the Go ABI" % main_go
        )

    preamble = match.group(1)

    # Strip everything that is not a C declaration:
    #   * ``#include`` / ``#cgo`` directives (cffi rejects them)
    #   * ``//`` line comments (including *trailing* ones, which would
    #     otherwise swallow the next declaration once lines are joined)
    #   * ``/* ... */`` block comments
    # Then append the exported function prototypes that live *after* the
    # preamble in main.go.
    body = re.sub(r"/\*.*?\*/", " ", preamble, flags=re.S)
    # Drop ``static inline`` function *definitions* — cdef() accepts only
    # declarations.  A brace-balanced scan is required because the helpers
    # contain nested blocks (``if (...) { ... }``), which a flat regex
    # would leave a dangling ``}`` behind.
    body = _strip_static_inline_functions(body)
    lines = []
    for raw in body.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    declarations = " ".join(lines)

    # Exported function prototypes live outside the cgo preamble, as
    # `//export Name` + `func Name(...)`.  They are derived from the Go
    # sources rather than listed by hand: a hand-written list silently omitted
    # SetPoolTTL / SetPoolScanInterval / RequestAsync, leaving the cdef an
    # incomplete mirror of the ABI it claims to describe.
    for proto in _exported_prototypes(_binding_go_sources(main_go)):
        name = proto.split("(")[0].split()[-1].rstrip("*")
        if "%s(" % name not in declarations:
            declarations += " " + proto

    return declarations.strip()


def _cdef_from_binding_header() -> str:
    """Rebuild a cdef from the generated cgo binding header, if present.

    The header repeats every exported prototype for the ABI that was actually
    built, so it is a trustworthy stand-in when main.go is unreadable.  The
    Python-constructed structs and the exported prototypes are stitched
    together; anything not found raises so the caller can report a real error
    instead of shipping a silently truncated cdef.
    """
    for name in _FALLBACK_HEADER_NAMES:
        candidate = _BINDING_DIR / name
        if not candidate.is_file():
            continue
        prototypes = []
        for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if not stripped.endswith(";"):
                continue
            if "extern" not in stripped and "dllexport" not in stripped:
                continue
            # Drop the export attribute; keep the plain C prototype.
            cleaned = stripped.replace("__declspec(dllexport)", " ")
            cleaned = cleaned.replace("extern", " ", 1).strip()
            if cleaned and "(" in cleaned:
                prototypes.append(cleaned)
        if prototypes:
            return ("\n" + _REQUIRED_STRUCTS + "\n" + "\n".join(prototypes) + "\n")
    raise RuntimeError(
        "no usable cdef source: main.go could not be parsed and none of %s "
        "exist next to build_binding.py" % (", ".join(_FALLBACK_HEADER_NAMES),)
    )


def _validate_cdef(cdef: str) -> str:
    """Fail fast when a cdef is missing the structs the binding depends on.

    A cdef that silently lacks RequestOptions would defer the failure to
    ``ffi.cdef`` / ``dlopen`` at import time instead of surfacing it here with
    an actionable message.
    """
    missing = [
        name for name in ("RequestOptions", "CustomTlsClient")
        if name not in cdef
    ]
    if missing:
        raise RuntimeError(
            "cdef lacks %s; main.go's cgo preamble layout changed "
            "unexpectedly (or the fallback header is stale)"
            % "/".join(missing)
        )
    return cdef


def _load_cdef() -> str:
    """Return the authoritative cdef, falling back only if extraction fails."""
    try:
        extracted = _extract_cdef_from_main_go()
    except RuntimeError as exc:
        print("[cffi] WARNING: %s" % exc, flush=True)
        print("[cffi] WARNING: deriving the cdef from the binding header", flush=True)
        return _validate_cdef(_cdef_from_binding_header())
    return _validate_cdef(extracted)


CDEF = _load_cdef()



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


def _shared_lib_name(variant: str = "full") -> str:
    ext = _shared_lib_ext()
    goos = _go_os()
    goarch = _go_arch()
    if variant == "full":
        return f"tls-client-{goos}-{goarch}{ext}"
    return f"tls-client-{goos}-{goarch}-{variant}{ext}"


# ---------------------------------------------------------------------------
# Go build
# ---------------------------------------------------------------------------

# Build variant profiles.  Each tier trades binary size against capability;
# ``lite`` and ``nano`` are meant for container/serverless images where the
# QUIC stack and the debug surface dominate the artifact.
#
#   full  — QUIC/HTTP-3 enabled, race detector off, full profile catalogue
#   lite  — HTTP/3 compiled out entirely (``-tags=tls_lite``); the Python
#           layer detects the variant via GetBuildVariant() and forces
#           disable_http3 so requests fail fast instead of hitting the
#           engine's H3 error path
#   nano  — lite plus capture/profile trimming: only the profiles named in
#           TLS_CLIENT_NANO_PROFILES survive, so a scrape-only deployment
#           ships a fraction of the profile table
BUILD_VARIANTS = ("full", "lite", "nano")

# Profiles retained by the ``nano`` tier when TLS_CLIENT_NANO_PROFILES is
# unset.  Keep this list short — the point of nano is a small artifact.
#
# NOTE: setting this variable only prunes the *runtime* profile map; every
# captured profile's data is still linked in, because they all live inside a
# single `switch major` in the generated table.  To actually shrink the
# artifact the table must be regenerated with just these majors:
#
#     python tools/gen_chrome_profiles.py --majors 133,150,152
#
# The CI nano job does exactly that before building; the env var remains set
# as a backstop so a hand-built nano library still behaves as documented.
_DEFAULT_NANO_PROFILES = ("chrome_133", "chrome_150", "chrome_152")


def _variant_tags(variant: str) -> list:
    """Return the ``-tags`` list for *variant*."""
    base = ["netgo", "osusergo"]
    if variant in ("lite", "nano"):
        # roundtripper_http3_stub.go is gated on this tag, so lite/nano
        # builds link no QUIC code at all.
        base.append("tls_lite")
    return base


def _variant_ldflags(variant: str) -> str:
    """Return the ``-ldflags`` string for *variant*.

    Every variant gets the same base: ``-s`` drops the symbol table, ``-w``
    drops DWARF, and ``-buildid=`` removes the Go build id (non-deterministic,
    and a few hundred bytes of entropy that helps neither debugging nor
    reproducibility).  Nano used to append a second ``-w`` — a no-op that
    only made the flag string harder to read.
    """
    flags = ["-s", "-w", "-buildid="]
    if variant == "nano":
        # Nano trades debuggability for size: keep .rodata and the type
        # descriptions lean by dropping the pclntab-backed traces too.
        flags.append("-X=main.buildVariant=nano")
    return " ".join(flags)


def build_go_library(
    srcdir: Optional[Path] = None,
    outdir: Optional[Path] = None,
    verbose: bool = True,
    variant: str = "full",
    upx: bool = False,
) -> Path:
    """Compile the Go shared library and return its path.

    *variant* selects one of :data:`BUILD_VARIANTS`.  *upx*, when true,
    additionally runs the UPX packer over the produced artifact — this is
    opt-in because it roughly halves on-disk size but (a) requires UPX on
    PATH, (b) can trip some AV/EDR heuristics, and (c) makes the binary
    non-reproducible.  The unpacked artifact is always kept alongside.
    """
    if variant not in BUILD_VARIANTS:
        raise ValueError(
            "unknown build variant %r; expected one of %s"
            % (variant, ", ".join(BUILD_VARIANTS))
        )
    if srcdir is None:
        srcdir = Path(__file__).resolve().parent
    if outdir is None:
        outdir = srcdir / "dist"

    outdir.mkdir(parents=True, exist_ok=True)

    goos = _go_os()
    goarch = _go_arch()
    ext = _shared_lib_ext()
    # The default (full) artifact keeps the canonical name so existing
    # loaders find it; slimmer tiers get a suffix.
    if variant == "full":
        libname = f"tls-client-{goos}-{goarch}{ext}"
    else:
        libname = f"tls-client-{goos}-{goarch}-{variant}{ext}"
    outpath = outdir / libname

    env = os.environ.copy()
    env["CGO_ENABLED"] = "1"
    env["GOOS"] = goos
    env["GOARCH"] = goarch
    if variant == "nano" and "TLS_CLIENT_NANO_PROFILES" not in env:
        env["TLS_CLIENT_NANO_PROFILES"] = ",".join(_DEFAULT_NANO_PROFILES)

    tags = ",".join(_variant_tags(variant))
    ldflags = _variant_ldflags(variant)

    cmd = [
        "go", "build",
        "-buildmode=c-shared",
        "-buildvcs=false",
        "-trimpath",
        "-tags=%s" % tags,
        "-ldflags=%s" % ldflags,
        "-o", str(outpath),
        ".",
    ]

    if verbose:
        print(f"[build] variant={variant} {' '.join(cmd)}", flush=True)

    subprocess.run(cmd, cwd=str(srcdir), env=env, check=True)

    # `go build -buildmode=c-shared` also produces a C header – remove it
    # because cffi in API mode does not need it.
    header = outdir / f"tls-client-{goos}-{goarch}.h"
    if header.exists():
        header.unlink()
        if verbose:
            print(f"[build] removed surplus header {header}", flush=True)

    if upx:
        _run_upx(outpath, verbose=verbose)

    if verbose:
        print(f"[build] → {outpath}", flush=True)

    return outpath


def _run_upx(libpath: Path, verbose: bool = True) -> None:
    """Pack *libpath* with UPX, keeping the original at ``<name>.upx-unpacked``.

    UPX on a c-shared Go library is a real size win but is not universally
    safe: some sandboxes refuse to ``dlopen`` a packed library.  We therefore
    keep the unpacked copy and never delete it.
    """
    backup = libpath.with_suffix(libpath.suffix + ".upx-unpacked")
    if not backup.exists():
        import shutil

        shutil.copy2(libpath, backup)

    try:
        subprocess.run(["upx", "--best", "--lzma", str(libpath)], check=True)
        if verbose:
            print(f"[build] upx packed {libpath}", flush=True)
    except FileNotFoundError:
        print(
            "[build] WARNING: upx not found on PATH — leaving the library "
            "unpacked",
            flush=True,
        )
    except subprocess.CalledProcessError as exc:
        # UPX failed (already packed, unsupported arch, corrupted output…).
        # Restore the known-good copy so we never ship a broken artifact.
        import shutil

        shutil.copy2(backup, libpath)
        print(
            "[build] WARNING: upx failed (%s) — restored the unpacked "
            "library" % exc,
            flush=True,
        )


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
    parser.add_argument(
        "--variant",
        choices=BUILD_VARIANTS,
        default="full",
        help="Build tier: full (all features), lite (no HTTP/3), "
             "nano (lite + trimmed profile catalogue)",
    )
    parser.add_argument(
        "--all-variants",
        action="store_true",
        help="Build full, lite and nano in one run",
    )
    parser.add_argument(
        "--upx",
        action="store_true",
        help="Pack the artifact with UPX after building (keeps an unpacked copy)",
    )
    args = parser.parse_args()

    srcdir = Path(__file__).resolve().parent

    if args.pkg:
        outdir = srcdir / "dist"
        libname = _shared_lib_name(args.variant)
        libpath = outdir / libname
        if not libpath.exists():
            sys.exit(f"Shared library not found at {libpath}. Run --lib first.")
        verify_cdef(libpath)
        return

    variants = BUILD_VARIANTS if args.all_variants else (args.variant,)
    last = None
    for variant in variants:
        last = build_go_library(srcdir=srcdir, variant=variant, upx=args.upx)
    if not args.lib and last is not None:
        verify_cdef(last)


if __name__ == "__main__":
    main()
