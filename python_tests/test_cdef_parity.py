"""cdef parity: the hand-maintained Python cdef vs. the one derived from Go.

``tls_client/_core.py`` carries its own ``CDEF`` string (it must be importable
without the build tooling).  ``cffi_binding/build_binding.py`` derives its cdef
directly from the ``import "C"`` preamble in ``main.go``.

If those two drift, cffi silently mis-marshals the appended ABI fields: a
request that sets ``extension_permute_mode`` would write into the wrong struct
offset and the wire fingerprint would not match what the caller asked for.
This test compares the *struct field layout* of both definitions and fails on
any divergence.

It is skipped when the build tooling cannot be imported (e.g. a wheel install
that ships no ``cffi_binding`` directory).
"""

import os
import re
import sys
import unittest

from tls_client._core import CDEF as CORE_CDEF

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BINDING_DIR = os.path.join(_REPO, "cffi_binding")


def _struct_fields(cdef: str, struct_name: str):
    """Return the ordered field names of ``struct_name`` from *cdef*.

    Returns ``None`` when the struct is absent.  Array suffixes are stripped so
    ``int foo[4]`` and ``int foo`` compare equal — only the field *name* and
    *order* matter for ABI layout parity.
    """
    match = re.search(
        r"typedef\s+struct\s*\{(.*?)\}\s*%s\s*;" % re.escape(struct_name),
        cdef,
        re.S,
    )
    if not match:
        return None
    body = re.sub(r"/\*.*?\*/", " ", match.group(1), flags=re.S)
    body = re.sub(r"//[^\n]*", " ", body)
    fields = []
    for decl in body.split(";"):
        decl = decl.strip()
        if not decl:
            continue
        decl = re.sub(r"\s*\[[^\]]*\]\s*$", "", decl)  # drop array size
        name = decl.split()[-1] if decl.split() else ""
        name = name.lstrip("*")
        if name:
            fields.append(name)
    return fields


def _binding_available() -> bool:
    return os.path.isfile(os.path.join(_BINDING_DIR, "build_binding.py")) and os.path.isfile(
        os.path.join(_BINDING_DIR, "main.go")
    )


@unittest.skipUnless(_binding_available(), "cffi_binding sources not present")
class CdefParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, _BINDING_DIR)
        try:
            import build_binding  # type: ignore
        except Exception as exc:  # pragma: no cover - import environment dependent
            raise unittest.SkipTest("cannot import build_binding: %s" % exc)
        cls.binding_cdef = build_binding.CDEF

    @classmethod
    def tearDownClass(cls):
        if _BINDING_DIR in sys.path:
            sys.path.remove(_BINDING_DIR)

    def test_custom_tls_client_layout_matches(self):
        core = _struct_fields(CORE_CDEF, "CustomTlsClient")
        binding = _struct_fields(self.binding_cdef, "CustomTlsClient")
        self.assertIsNotNone(core, "_core.py lacks CustomTlsClient")
        self.assertIsNotNone(binding, "derived cdef lacks CustomTlsClient")
        self.assertEqual(core, binding)

    def test_request_options_layout_matches(self):
        core = _struct_fields(CORE_CDEF, "RequestOptions")
        binding = _struct_fields(self.binding_cdef, "RequestOptions")
        self.assertIsNotNone(core, "_core.py lacks RequestOptions")
        self.assertIsNotNone(binding, "derived cdef lacks RequestOptions")
        self.assertEqual(core, binding)

    def test_abi3_fields_present_in_both(self):
        """The ABI 3 fields must exist in both definitions, in the same order."""
        abi3 = [
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
        ]
        for cdef, label in ((CORE_CDEF, "core"), (self.binding_cdef, "binding")):
            fields = _struct_fields(cdef, "RequestOptions")
            tail = fields[-len(abi3):]
            self.assertEqual(tail, abi3, "%s RequestOptions ABI 3 tail mismatch" % label)

    def test_custom_tls_client_has_no_permute_fields(self):
        """Extension permutation is a RequestOptions policy, not a ClientHello field.

        `CustomTlsClient.extension_permute_mode/prefix` existed but no Go code
        ever read them; the permutation is consumed from RequestOptions.  The
        pair must stay out of BOTH definitions so the struct keeps its compact
        layout (and so nobody re-adds a write-only field).
        """
        for cdef, label in ((CORE_CDEF, "core"), (self.binding_cdef, "binding")):
            fields = _struct_fields(cdef, "CustomTlsClient")
            self.assertNotIn(
                "extension_permute_mode", fields,
                "%s CustomTlsClient regained the write-only extension_permute_mode" % label,
            )
            self.assertNotIn(
                "extension_permute_prefix", fields,
                "%s CustomTlsClient regained the write-only extension_permute_prefix" % label,
            )


if __name__ == "__main__":
    unittest.main()
