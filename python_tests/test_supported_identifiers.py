# -*- coding: utf-8 -*-
"""The identifier allowlist must cover what the engine can actually do.

Regression guard for a gap that existed before the 1.18.1 sync: the allowlist
was derived from the default-header table, so the captured Chrome profiles
without a hand-written header block were rejected by Session() and by
`fingerprints.apply()` even though the engine registers them and the preset
carries its own User-Agent.  35 of the 55 captured majors were unusable.
"""

import unittest

import tls_client
from tls_client.fingerprints import list_presets, resolve


class SupportedIdentifierTests(unittest.TestCase):
    def test_every_captured_chrome_major_is_accepted(self):
        # The engine registers chrome_99..chrome_153 from the capture table;
        # each one must be selectable from Python.
        for major in range(99, 154):
            for name in ("chrome_%d" % major, "chrome_%d_PSK" % major):
                self.assertIn(
                    name,
                    tls_client.SUPPORTED_CLIENT_IDENTIFIERS,
                    "%s is registered by the engine but rejected by Python" % name,
                )

    def test_every_chrome_preset_can_be_applied(self):
        presets = [
            n for n in list_presets()
            if n.startswith("chrome_") and n.endswith("_windows")
        ]
        self.assertGreater(len(presets), 50, "captured chrome presets went missing")
        for name in sorted(presets):
            session = tls_client.Session()
            # apply() resolves the preset's client_identifier through the same
            # validation Session() uses, so this catches the gap above.
            tls_client.fingerprints.apply(session, name)
            want = resolve(name)["client_identifier"]
            self.assertEqual(session.client_identifier, want, name)

    def test_the_new_profile_identifiers_are_selectable(self):
        for name in ("chrome_153", "chrome_154", "chrome_154_PSK", "safari_27_2"):
            self.assertIn(name, tls_client.SUPPORTED_CLIENT_IDENTIFIERS)


if __name__ == "__main__":
    unittest.main()
