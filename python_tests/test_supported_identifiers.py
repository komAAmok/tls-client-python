# -*- coding: utf-8 -*-
"""The identifier allowlist must track the capture table, not the header table.

Two separate histories are pinned here.

1. Regression guard for a gap that existed before the 1.18.1 sync: the
   allowlist was derived from `DEFAULT_HEADERS`, so the captured Chrome
   profiles without a hand-written header block were rejected by Session() and
   by `fingerprints.apply()` even though the engine registers them and the
   preset carries its own User-Agent.  35 of the 55 captured majors were
   unusable, and with them 35 of the 55 Chrome presets.

2. Drift guard for the fix itself.  The allowlist is now derived from
   `chrome_full.CAPTURED_CHROME_MAJORS`, which the preset generator writes from
   `tools/_chrome_captures.json`.  A new capture therefore widens the allowlist
   automatically -- but if someone hand-edits the generated module, or the
   engine's registry moves, these tests fail instead of the mismatch reaching a
   user as a ValueError or a runtime engine error.
"""

import unittest

import tls_client
from tls_client.fingerprints import list_presets, resolve
from tls_client.fingerprints.chrome_full import CAPTURED_CHROME_MAJORS


class CapturedIdentifierTests(unittest.TestCase):
    def test_allowlist_covers_every_capture(self):
        self.assertTrue(CAPTURED_CHROME_MAJORS, "no captured majors were exposed")
        for major in CAPTURED_CHROME_MAJORS:
            for name in ("chrome_%d" % major, "chrome_%d_PSK" % major):
                self.assertIn(
                    name,
                    tls_client.SUPPORTED_CLIENT_IDENTIFIERS,
                    "%s is in the capture table but rejected by Python" % name,
                )

    def test_allowlist_does_not_invent_identifiers(self):
        """Python must not accept anything the engine has not registered.

        A wider allowlist is worse than a narrow one: Session() succeeds and the
        engine fails at request time instead, which is harder to attribute.
        """
        for name in tls_client.SUPPORTED_CLIENT_IDENTIFIERS:
            if name.startswith("chrome_"):
                self.assertTrue(
                    name in ("chrome_153", "chrome_153_PSK")
                    or name in ("chrome_154", "chrome_154_PSK")
                    or any(
                        name == "chrome_%d" % m or name == "chrome_%d_PSK" % m
                        for m in CAPTURED_CHROME_MAJORS
                    )
                    or name in _HAND_WRITTEN_CHROME,
                    "%s is accepted by Python but is neither captured nor "
                    "hand-written" % name,
                )

    def test_every_chrome_preset_can_be_applied(self):
        presets = [
            n for n in list_presets()
            if n.startswith("chrome_") and n.endswith("_windows")
        ]
        self.assertEqual(
            len(presets),
            len(CAPTURED_CHROME_MAJORS),
            "one preset per captured major, plus none",
        )
        for name in sorted(presets):
            session = tls_client.Session()
            # apply() resolves the preset's client_identifier through the same
            # validation Session() uses, so this is where the gap above showed.
            tls_client.fingerprints.apply(session, name)
            self.assertEqual(
                session.client_identifier, resolve(name)["client_identifier"], name
            )

    def test_no_preset_is_rejected(self):
        """The whole preset catalogue, not just Chrome."""
        failures = []
        for name in sorted(list_presets()):
            session = tls_client.Session()
            try:
                tls_client.fingerprints.apply(session, name)
            except Exception as exc:  # report every failure at once
                failures.append("%s: %s: %s" % (name, type(exc).__name__, exc))
        self.assertEqual(failures, [])

    def test_the_new_profile_identifiers_are_selectable(self):
        for name in ("chrome_153", "chrome_154", "chrome_154_PSK", "safari_27_2"):
            self.assertIn(name, tls_client.SUPPORTED_CLIENT_IDENTIFIERS)


# Chrome identifiers that exist as hand-written profiles rather than captures:
# the milestones with PSK / Post-Quantum / trust-anchor refinements.
_HAND_WRITTEN_CHROME = frozenset((
    "chrome_116_PSK",
    "chrome_116_PSK_PQ",
    "chrome_130_PSK",
    "chrome_131",
    "chrome_131_PSK",
    "chrome_133",
    "chrome_133_PSK",
    "chrome_144",
    "chrome_144_PSK",
    "chrome_146",
    "chrome_146_PSK",
    "chrome_150",
    "chrome_150_PSK",
    "chrome_152",
    "chrome_152_PSK",
))


if __name__ == "__main__":
    unittest.main()
