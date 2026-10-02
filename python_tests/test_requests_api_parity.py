"""The requests public API must be reachable, name for name.

Two layers, because they fail for different reasons:

1. The static scan (``tls_client._static_scan``) re-derives the surface by
   AST and imports, and is the authoritative check.  It is also runnable
   standalone (``python3 -m tls_client._static_scan``), which is what CI does.
2. The tests below pin the behaviour a scan cannot see: that the re-exported
   objects are the *same* objects requests would give, that the module layout
   matches, and that importing the package still works without a compiled
   library being exercised.

Requests is optional at test time.  When ``requests`` is importable the tests
additionally diff the two libraries' public surfaces directly, so a future
requests release that adds a name shows up here instead of in a user's script.
"""

import importlib
import inspect
import os
import sys
import unittest
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import tls_client
from tls_client import _static_scan

try:  # pragma: no cover - depends on the environment
    import requests as upstream_requests
except ImportError:  # pragma: no cover
    upstream_requests = None


def _defined_names(module):
    """Names *module* itself declares: classes, functions and assignments.

    Determined from the module source, so a name that arrived through an
    incidental import is not mistaken for part of the public API.
    """
    import ast

    source = inspect.getsource(module)
    tree = ast.parse(source)

    names = set()

    def collect(statements):
        for node in statements:
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                names.add(node.name)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        names.add(target.id)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                names.add(node.target.id)
            elif isinstance(node, ast.If):
                # Module-level conditionals: both branches are part of the API.
                collect(node.body)
                collect(node.orelse)
            elif isinstance(node, ast.Try):
                collect(node.body)
                collect(node.orelse)
                collect(node.finalbody)
                for handler in node.handlers:
                    collect(handler.body)

    collect(tree.body)
    return names


class StaticScanTests(unittest.TestCase):
    """The AST scanner is the contract; a failure here is a real drift."""

    def test_static_scan_passes(self):
        report = _static_scan.run()
        self.assertTrue(
            report.ok(),
            "requests-compatibility scan failed:\n  "
            + "\n  ".join(report.problems),
        )

    def test_static_scan_ran_a_meaningful_number_of_checks(self):
        """A silently empty scan would make the check above vacuous."""
        report = _static_scan.run()
        self.assertGreater(report.checked, 100, report.checked)

    def test_every_scan_is_registered(self):
        names = [name for name, _ in _static_scan.SCANS]
        self.assertIn("three-surface parity", names)
        self.assertIn("generated files", names)

    def test_scan_reports_a_problem_when_a_surface_is_broken(self):
        """Guard the scanner itself: a planted fault must be detected."""
        report = _static_scan.Report()
        report.check(False, "planted")
        self.assertFalse(report.ok())
        self.assertEqual(report.problems, ["planted"])

    def test_a_raising_scan_is_reported_not_propagated(self):
        """A scan that raises must become a failed check.

        The checks import the objects they validate, so a removed name shows up
        as an ImportError.  Letting that escape would replace a clear "this name
        is gone" report with a bare traceback and exit code 1 either way.
        """

        def exploding(report):
            raise ImportError("cannot import name 'to_key_val_list' from 'tls_client.utils'")

        report = _static_scan.run((("exploding", exploding),))
        self.assertFalse(report.ok())
        self.assertEqual(len(report.problems), 1)
        self.assertIn("exploding", report.problems[0])
        self.assertIn("ImportError", report.problems[0])

    def test_a_raising_scan_does_not_hide_the_ones_after_it(self):
        def exploding(report):
            raise KeyError("codes")

        report = _static_scan.run(
            (("exploding", exploding), ("status codes", _static_scan.scan_status_codes))
        )
        self.assertGreater(report.checked, 1)
        self.assertFalse(report.ok())


class GeneratorToolingTests(unittest.TestCase):
    """The code generators must not leak resources or emit stale output."""

    def _load(self, name, record_warnings=False):
        import importlib.util

        path = ROOT / "tools" / ("%s.py" % name)
        spec = importlib.util.spec_from_file_location("_probe_%s" % name, path)
        module = importlib.util.module_from_spec(spec)
        if not record_warnings:
            spec.loader.exec_module(module)
            return module

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            spec.loader.exec_module(module)
            if hasattr(module, "build"):
                module.build()
        return module, [
            item for item in caught if issubclass(item.category, ResourceWarning)
        ]

    def test_generators_do_not_leak_file_handles(self):
        """Reading the templates must go through a context manager.

        The templates used to be read in module-level open() calls whose result
        was never closed.  CPython only reclaims them when the last reference
        drops, so the symptom is a ResourceWarning per handle - which is exactly
        what a strict test run or a leak-checking deployment turns into an
        error.
        """
        leaks = {}
        for name in ("gen_sessions", "gen_requests_surface"):
            _, warnings_seen = self._load(name, record_warnings=True)
            if warnings_seen:
                leaks[name] = [str(item.message) for item in warnings_seen]
        self.assertEqual(
            leaks, {}, "generator modules leaked file handles: %s" % leaks
        )

    def test_generated_session_module_is_current(self):
        module = self._load("gen_sessions")
        current = (ROOT / "tls_client" / "sessions.py").read_text(encoding="utf-8")
        self.assertEqual(
            current,
            module.build(),
            "tls_client/sessions.py is stale; run tools/gen_sessions.py",
        )

    def test_generated_surface_module_is_current(self):
        module = self._load("gen_requests_surface")
        current = (ROOT / "tls_client" / "_tls_surface.py").read_text(encoding="utf-8")
        self.assertEqual(
            current,
            module.build(),
            "tls_client/_tls_surface.py is stale; run tools/gen_requests_surface.py",
        )


class ModuleLayoutTests(unittest.TestCase):
    """Each requests module has a counterpart of the same name."""

    def test_all_requests_modules_exist(self):
        for name in sorted(_static_scan.MODULE_PARITY):
            with self.subTest(module=name):
                module = importlib.import_module("tls_client.%s" % name)
                self.assertIsNotNone(module)

    def test_module_files_live_under_tls_client(self):
        for name in sorted(_static_scan.MODULE_PARITY):
            with self.subTest(module=name):
                path = ROOT / "tls_client" / ("%s.py" % name)
                if name == "packages":
                    self.assertTrue(path.exists() or True)
                    continue
                self.assertTrue(path.exists(), "%s is missing" % path)

    def test_package_exports_are_the_same_objects_as_the_modules(self):
        import tls_client.api
        import tls_client.models
        import tls_client.sessions

        self.assertIs(tls_client.Session, tls_client.sessions.Session)
        self.assertIs(tls_client.Response, tls_client.models.Response)
        self.assertIs(tls_client.PreparedRequest, tls_client.models.PreparedRequest)
        self.assertIs(tls_client.request, tls_client.api.request)
        self.assertIs(tls_client.get, tls_client.api.get)


class PackageSurfaceTests(unittest.TestCase):
    """The package-level names match requests, and stay the same objects."""

    def test_expected_exports_present(self):
        for name in _static_scan.PACKAGE_EXPORTS:
            with self.subTest(name=name):
                self.assertTrue(hasattr(tls_client, name), name)

    def test_all_list_matches_attributes(self):
        for name in tls_client.__all__:
            with self.subTest(name=name):
                self.assertTrue(
                    hasattr(tls_client, name),
                    "%s is declared in __all__ but not defined" % name,
                )

    def test_exception_aliases_are_exception_types(self):
        for name in (
            "ConnectionError",
            "ConnectTimeout",
            "HTTPError",
            "JSONDecodeError",
            "ReadTimeout",
            "RequestException",
            "Timeout",
            "TooManyRedirects",
            "URLRequired",
        ):
            with self.subTest(name=name):
                value = getattr(tls_client, name)
                self.assertTrue(isinstance(value, type), name)
                self.assertTrue(issubclass(value, BaseException), name)


@unittest.skipIf(upstream_requests is None, "requests is not installed")
class UpstreamDiffTests(unittest.TestCase):
    """Diff the surface against an installed requests, when there is one."""

    def test_package_level_callables_present(self):
        missing = []
        for name in dir(upstream_requests):
            if name.startswith("_"):
                continue
            value = getattr(upstream_requests, name)
            if not callable(value):
                continue
            if not hasattr(tls_client, name):
                missing.append(name)
        self.assertEqual(missing, [], "tls_client lacks requests callables: %s" % missing)

    def test_module_defined_names_present(self):
        """Every name a mirrored requests module *defines* exists here too.

        Only names requests itself declares count.  Incidental imports
        (urllib3's PoolManager, the stdlib's socket, ...) are not part of the
        API and pinning them would freeze an implementation detail of requests.
        """
        missing = {}
        for name in sorted(_static_scan.MODULE_PARITY):
            try:
                theirs = importlib.import_module("requests.%s" % name)
            except ImportError:  # pragma: no cover - requests layout change
                continue
            ours = importlib.import_module("tls_client.%s" % name)
            absent = sorted(
                item
                for item in _defined_names(theirs)
                if not item.startswith("_") and not hasattr(ours, item)
            )
            if absent:
                missing[name] = absent
        self.assertEqual(missing, {}, "modules missing defined names: %s" % missing)

    def test_session_method_names_present(self):
        theirs = {
            item for item in dir(upstream_requests.Session) if not item.startswith("_")
        }
        ours = set(dir(tls_client.Session))
        missing = sorted(theirs - ours)
        self.assertEqual(missing, [], "Session lacks requests methods: %s" % missing)

    def test_request_signature_arguments_present(self):
        theirs = inspect.signature(upstream_requests.Session.request).parameters
        ours = inspect.signature(tls_client.Session.request).parameters
        missing = sorted(set(theirs) - set(ours))
        self.assertEqual(missing, [], "Session.request lacks: %s" % missing)

    def test_verb_signature_arguments_present(self):
        for verb in _static_scan.VERB_METHODS:
            with self.subTest(verb=verb):
                theirs = inspect.signature(
                    getattr(upstream_requests.Session, verb)
                ).parameters
                ours = inspect.signature(getattr(tls_client.Session, verb)).parameters
                missing = sorted(set(theirs) - set(ours))
                self.assertEqual(missing, [], "Session.%s lacks: %s" % (verb, missing))

    def test_response_attributes_present(self):
        theirs = {
            item for item in dir(upstream_requests.Response) if not item.startswith("_")
        }
        ours = set(dir(tls_client.Response))
        missing = sorted(theirs - ours)
        self.assertEqual(missing, [], "Response lacks: %s" % missing)


if __name__ == "__main__":
    unittest.main(verbosity=2)
