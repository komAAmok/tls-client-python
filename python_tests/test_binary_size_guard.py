"""Guards the shared library against silent size regressions.

The binaries are large because the engine is a full-fidelity TLS client, so the
guard does not pin an absolute size -- that would break on every legitimate
dependency bump.  It pins the *structure* that the size work depends on:

  * ``html/charset`` must not come back, because it links the whole
    ``x/text/encoding`` registry (all legacy codecs plus both directions of the
    CJK tables) for a transcode that only runs behind ``with_debug``.
  * The lean replacement must keep calling ``NewDecoder()`` directly.  Storing
    those methods as values (a map of method values, or an
    ``encoding.Encoding`` table) keeps the interface itabs alive and with them
    the encode tables, which gives back most of the saving.

Both checks read source, so they run on any host without a Go toolchain.
"""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CHARSET_LEAN = ROOT / "charset_lean.go"
CLIENT_GO = ROOT / "client.go"


class CharsetImportTests(unittest.TestCase):
    """html/charset pulls ~3.7 MB of encoding tables for a debug-only path."""

    def test_client_does_not_import_html_charset(self):
        source = CLIENT_GO.read_text(encoding="utf-8")
        offending = [
            (i, line.strip())
            for i, line in enumerate(source.splitlines(), 1)
            if line.strip() == '"golang.org/x/net/html/charset"'
        ]
        self.assertEqual(
            offending,
            [],
            "client.go imports html/charset again (line, text)=%s; that links "
            "the whole x/text/encoding registry for the debug-only body preview"
            % (offending,),
        )

    def test_client_uses_the_lean_reader(self):
        """client.go must reach the charset decode through charset_lean.go.

        The debug preview calls decodeBodyForLog (which uses newCharsetReader),
        and the response body itself is never rewritten - see the LOCAL OVERLAY
        note in client.go.  Either name is fine here; what matters is that the
        html/charset import does not come back.
        """
        source = CLIENT_GO.read_text(encoding="utf-8")
        self.assertTrue(
            "decodeBodyForLog(" in source or "newCharsetReader(" in source,
            "client.go no longer calls the lean charset reader",
        )

    def test_no_non_test_file_imports_html_charset(self):
        offenders = []
        for path in sorted(ROOT.rglob("*.go")):
            rel = path.relative_to(ROOT).as_posix()
            if rel.startswith("third_party/") or rel.endswith("_test.go"):
                continue
            # .cache/ holds the Go module cache (gitignored), and the
            # third_party/ fhttp tree is vendored; neither is built into the
            # shared library, and scanning them makes the check depend on
            # whether the developer has warmed the module cache.
            if rel.startswith(".cache/"):
                continue
            if "/x/text/encoding" in path.read_text(encoding="utf-8", errors="ignore"):
                if rel != "charset_lean.go":
                    offenders.append(rel)
        self.assertEqual(
            offenders,
            [],
            "only charset_lean.go may import x/text/encoding; "
            "other importers re-link the encode tables",
        )


class DecoderDevirtualisationTests(unittest.TestCase):
    """NewDecoder must be called directly so the encode tables stay unlinked."""

    def setUp(self):
        self.source = CHARSET_LEAN.read_text(encoding="utf-8")

    def test_no_table_of_method_values(self):
        # A map/slice of `X.NewDecoder` (no call parentheses) keeps the
        # encoding.Encoding itab, and the itab carries NewEncoder.
        table_of_methods = re.search(
            r"(map|\[\])[^\n]*func\(\)\s*\*?encoding\.Decoder", self._code_only()
        )
        self.assertIsNone(
            table_of_methods,
            "charset_lean.go stores NewDecoder as a value; call it directly "
            "in the switch instead so the encode tables stay unlinked",
        )

    def test_decoders_are_invoked_not_referenced(self):
        code = self._code_only()
        calls = len(re.findall(r"\.NewDecoder\(\)", code))
        bare = re.findall(r"\.NewDecoder\b(?!\s*\()", code)
        self.assertEqual(
            bare, [], "these NewDecoder references are not calls: %s" % bare
        )
        self.assertGreater(calls, 0, "no NewDecoder() call found")

    def test_no_encoding_encoding_table(self):
        # Holding encoding.Encoding values re-links every encoder in the same
        # struct, so the CJK encode tables come back.  Code only: the doc
        # comment discusses the construct it warns about.
        code = self._code_only()
        offenders = re.findall(r"\[\]?encoding\.Encoding\b", code)
        self.assertEqual(
            offenders,
            [],
            "charset_lean.go holds encoding.Encoding values; "
            "that re-links the encode halves",
        )

    def _code_only(self):
        """The file with comments stripped, so prose cannot trip the checks."""
        without_block = re.sub(r"/\*.*?\*/", "", self.source, flags=re.S)
        return "\n".join(
            line for line in without_block.splitlines()
            if not line.lstrip().startswith("//")
        )


class ShippedBinaryTests(unittest.TestCase):
    """The committed binaries should carry the lean build, not the old one."""

    def test_linux_amd64_binary_stays_under_budget(self):
        target = ROOT / "tls_client" / "bin" / "tls-client-linux-amd64.so"
        if not target.exists():
            self.skipTest("no committed linux/amd64 binary in this checkout")
        # Measured 13,984,760 bytes with the lean charset and 14,095,224 with
        # html/charset — a ~110 KB gap that the budget sat inside, so a
        # regression to the fat build failed while an ordinary dependency bump
        # did not.
        #
        # The lean reader decodes every label html/charset does, so it is
        # larger than the decode-only subset it replaced (13,812,184): the
        # <meta> prescan needs x/net/html's tokenizer (~24 KB) and the label
        # table covers the whole htmlindex catalogue.  It still avoids the
        # ~260 KB of encode tables that referencing htmlindex directly pulls in.
        #
        # Upstream 1.18.1 sync re-baselines this number.  Measured 15,016,072
        # bytes on linux/amd64 (+1,035,440, +7.4 %) for these reasons, none of
        # them charset related:
        #   * utls 1.7.8 -> 1.8.2-barnius: ML-KEM (X25519MLKEM768) and ML-DSA
        #     signature algorithms, now referenced by the Chrome 152+ profiles;
        #   * klauspost/compress 1.18.2 -> 1.20.1 plus upstream's
        #     "gzip, deflate, br, zstd" Accept-Encoding, which links the zstd
        #     decoder/encoder and its huff0/fse tables;
        #   * golang.org/x/net 0.48 -> 0.59 and x/text 0.32 -> 0.42;
        #   * the new trust_anchors package, which embeds the Chrome Root
        #     Store anchor list for the 0xCA34 extension;
        #   * new captures (Chrome 154, Safari 27.2) in the profile catalogue.
        #
        # The discriminator this test exists for is still exact: the budget is
        # 15,100,000, which the fat build would exceed once the ~110 KB
        # html/charset block is linked back on top of the new baseline
        # (15,016,072 + 110,000 > 15,100,000).  The whitespace-free check in
        # CharsetLeanTests above pins the actual property; this one catches the
        # case where charset_lean.go is bypassed wholesale.
        budget = 15_100_000
        size = target.stat().st_size
        self.assertLess(
            size,
            budget,
            "%s is %d bytes (budget %d); it may have been rebuilt with "
            "html/charset linked back in" % (target.name, size, budget),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
