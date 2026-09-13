"""Every symbol the CDEF declares must be exported by the compiled binding.

`tls_client/_core.py` ships one hand-written CDEF for the single full build
and gates ABI-version features at runtime through `_require_abi2()` and
`_degrade_abi3_fields()`.  A build tag therefore may not silently remove an
exported symbol: `cffi` resolves the whole CDEF when the library is loaded,
so a missing export turns a documented degradation into a hard load failure.

Two levels of checking, because they have different cost and freshness:

1. **Source level (always runs).**  Resolve which Go files the build actually
   compiles (by build tag) and assert every CDEF symbol carries an
   `//export` directive in one of them.  This needs no compiler and is the
   authoritative check.

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
}


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
        """Source level: the compiled binding files export every CDEF symbol."""
        # The single full build compiles every binding .go file (there is no
        # tls_lite / nano tier), except the pure-Go !cgo stub which is not
        # part of the c-shared ABI.
        selected = [
            text for name, (text, tag) in self.sources.items()
            if tag != "!cgo"
        ]
        exported = _exported_in_sources(selected)
        missing = sorted(self.declared - exported)
        considered = sorted(
            n for n, (_, t) in self.sources.items() if t != "!cgo"
        )
        self.assertEqual(
            missing, [],
            f"binding sources do not export CDEF symbols: {missing} "
            f"(files considered: {considered})",
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
