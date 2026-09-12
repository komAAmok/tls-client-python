"""Every symbol the CDEF declares must be exported by every build variant.

`tls_client/_core.py` ships one hand-written CDEF for all three build
variants (full / lite / nano) and gates features at runtime through
`_require_abi2()` and `_degrade_abi3_fields()`.  A build tag therefore may
not silently remove an exported symbol: `cffi` resolves the whole CDEF when
the library is loaded, so a missing export turns a documented "returns None
in the lite build" degradation into a hard load failure.

This regressed once already — the `tls_lite` ECH stub defined a private
`resolveECHConfigLite` with no `//export` directive, so a lite build lost
`ResolveECHConfig` entirely while the CDEF still declared it.

Two levels of checking, because they have different cost and freshness:

1. **Source level (always runs).**  For each variant, resolve which Go files
   that variant actually compiles (by build tag) and assert every CDEF symbol
   carries an `//export` directive in one of them.  This needs no compiler and
   is the authoritative check.

2. **Artifact level (only when fresh).**  The generated `.h` files in
   `tls_client/bin/` are build outputs that lag the source between a source
   change and the next build.  They are only asserted when the header is newer
   than the newest Go source, so a deliberately stale checked-in artifact does
   not produce a false failure.
"""

import os
import re
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_BIN_DIR = os.path.join(_ROOT, "tls_client", "bin")
_BINDING_DIR = os.path.join(_ROOT, "cffi_binding")
_CORE_PY = os.path.join(_ROOT, "tls_client", "_core.py")

# Variant name -> header file produced by that variant's build.
_VARIANTS = {
    "full": "tls-client-windows-amd64.h",
    "lite": "tls-client-windows-amd64-lite.h",
    "nano": "tls-client-windows-amd64-nano.h",
}

# Build tag that excludes a file from the lite/nano variants.
_LITE_TAG = "tls_lite"


def _cdef_function_names():
    """Return the set of C function names declared in _core.py's CDEF."""
    with open(_CORE_PY, "r", encoding="utf-8") as fh:
        src = fh.read()

    names = set()
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\([^;{)]*\)\s*;", src):
        names.add(match.group(1))

    keywords = {
        "if", "for", "while", "switch", "return", "sizeof", "typedef",
        "void", "int", "char", "unsigned", "long", "short", "const",
        "struct", "union", "enum",
    }
    return {n for n in names if n not in keywords}


def _binding_sources():
    """Return {filename: (text, build_tag_or_None)} for binding .go files."""
    out = {}
    for name in sorted(os.listdir(_BINDING_DIR)):
        if not name.endswith(".go") or name.endswith("_test.go"):
            continue
        path = os.path.join(_BINDING_DIR, name)
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        tag = None
        match = re.search(r"^//go:build\s+(.+)$", text, re.M)
        if match:
            tag = match.group(1).strip()
        out[name] = (text, tag)
    return out


def _compiled_for_variant(tag, variant):
    """Whether a file with build constraint *tag* is compiled for *variant*."""
    if tag is None:
        return True
    wants_lite = variant in ("lite", "nano")
    # Only the tags this package actually uses need interpreting.
    if tag == _LITE_TAG:
        return wants_lite
    if tag == "!" + _LITE_TAG:
        return not wants_lite
    if tag == "!cgo":
        # The pure-Go stub is for `go build` without cgo; the shared library
        # is always built with cgo enabled, so it is not part of the ABI.
        return False
    return True


def _exported_in_sources(sources):
    """Set of names carrying an ``//export`` directive in *sources*."""
    names = set()
    for text in sources:
        names.update(re.findall(r"^//export\s+(\w+)", text, re.M))
    return names


def _exported_in_header(header_path):
    """Set of symbol names a generated cgo header exports."""
    names = set()
    with open(header_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if "extern" not in line and "dllexport" not in line:
                continue
            match = re.search(r"\b([A-Za-z_]\w*)\s*\(([^()]*)\)\s*;\s*$", line)
            if match:
                names.add(match.group(1))
    return names


def _newest_go_source_mtime():
    newest = 0.0
    for directory in (_BINDING_DIR, _ROOT):
        for name in os.listdir(directory):
            if name.endswith(".go"):
                newest = max(newest, os.path.getmtime(os.path.join(directory, name)))
    return newest


class ExportParityTests(unittest.TestCase):
    def setUp(self):
        self.declared = _cdef_function_names()
        self.sources = _binding_sources()

    def test_cdef_parsed(self):
        """Guard the regex: a silent parse failure would void every check."""
        self.assertIn("ResolveECHConfig", self.declared)
        self.assertIn("ExecuteRequest", self.declared)
        self.assertGreater(len(self.declared), 5)

    def test_every_variant_exports_every_declared_symbol(self):
        """Source level: each variant's compiled files export the CDEF."""
        for variant in sorted(_VARIANTS):
            selected = [
                text for text, tag in self.sources.values()
                if _compiled_for_variant(tag, variant)
            ]
            exported = _exported_in_sources(selected)
            missing = sorted(self.declared - exported)
            considered = sorted(
                n for n, (_, t) in self.sources.items()
                if _compiled_for_variant(t, variant)
            )
            self.assertEqual(
                missing, [],
                f"variant {variant!r} does not export CDEF symbols: "
                f"{missing} (files considered: {considered})",
            )

    def test_lite_stub_exports_ech(self):
        """Regression: the tls_lite stub must keep the exported ECH symbol."""
        stub = self.sources.get("ech_stub.go")
        if stub is None:
            self.skipTest("ech_stub.go not present")
        text, tag = stub
        self.assertEqual(tag, _LITE_TAG, "ech_stub.go must be tls_lite-gated")
        self.assertIn(
            "//export ResolveECHConfig", text,
            "the lite ECH stub must export ResolveECHConfig (the CDEF declares "
            "it unconditionally, so omitting it breaks dlopen on a lite build)",
        )

    def test_generated_headers_export_every_declared_symbol(self):
        """Artifact level, only for headers newer than the newest Go source."""
        newest_source = _newest_go_source_mtime()
        checked = 0
        for variant, name in sorted(_VARIANTS.items()):
            path = os.path.join(_BIN_DIR, name)
            if not os.path.exists(path):
                continue
            if os.path.getmtime(path) < newest_source:
                # Stale artifact: it predates the current source and will be
                # regenerated by the next build.  The source-level test above
                # already covers correctness.
                continue
            checked += 1
            missing = sorted(self.declared - _exported_in_header(path))
            self.assertEqual(
                missing, [],
                f"variant {variant!r} ({name}) does not export CDEF symbols: "
                f"{missing}",
            )
        if checked == 0:
            self.skipTest(
                "no freshly-built headers in tls_client/bin/ (all stale); "
                "the source-level check above is authoritative"
            )


if __name__ == "__main__":
    unittest.main()
