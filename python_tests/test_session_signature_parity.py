"""Session and AsyncSession must expose the same constructor surface.

`AsyncSession` is a thin wrapper that constructs a `Session` and forwards
every argument to it.  When the two constructor signatures drift, the async
client silently cannot express a configuration the sync client can — a
caller passing `tcp_no_delay=0` to `AsyncSession` gets a `TypeError` while
the identical call on `Session` works.

That is exactly what happened for the 14 ABI 2.1 / ABI 3 knobs: the deep
TCP fingerprint fields, extension permutation, PRIORITY-frame suppression
and destination-aware header ordering were all added to `Session` only.

This test compares the two signatures by name and by order, so a future
knob added to one side and forgotten on the other fails loudly here rather
than in a user's async script.
"""

import ast
import os
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_CORE_PY = os.path.join(os.path.dirname(_HERE), "tls_client", "_core.py")


def _init_params(cls_name):
    """Return the ordered parameter names of `cls_name.__init__`."""
    with open(_CORE_PY, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read())

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == cls_name:
            for item in node.body:
                if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if item.name != "__init__":
                    continue
                args = item.args
                ordered = args.posonlyargs + args.args + args.kwonlyargs
                return [a.arg for a in ordered if a.arg != "self"]
    raise AssertionError(
        f"could not find {cls_name}.__init__ in {_CORE_PY}"
    )


class SessionSignatureParityTests(unittest.TestCase):
    def setUp(self):
        self.sync = _init_params("Session")
        self.async_ = _init_params("AsyncSession")

    def test_parse_guard(self):
        """A parse failure would make the parity checks vacuous."""
        self.assertGreater(len(self.sync), 20)
        self.assertGreater(len(self.async_), 20)

    def test_no_parameter_missing_from_async(self):
        missing = sorted(set(self.sync) - set(self.async_))
        self.assertEqual(
            missing, [],
            "AsyncSession.__init__ is missing parameters that Session "
            f"accepts: {missing}",
        )

    def test_no_parameter_missing_from_sync(self):
        extra = sorted(set(self.async_) - set(self.sync))
        self.assertEqual(
            extra, [],
            "AsyncSession.__init__ accepts parameters that Session does "
            f"not: {extra}",
        )

    def test_declaration_order_matches(self):
        shared_sync = [n for n in self.sync if n in set(self.async_)]
        shared_async = [n for n in self.async_ if n in set(self.sync)]
        self.assertEqual(
            shared_sync, shared_async,
            "Session and AsyncSession declare their shared parameters in "
            "different orders; keyword-only callers are unaffected but the "
            "drift usually hides a real mismatch.",
        )


if __name__ == "__main__":
    unittest.main()
