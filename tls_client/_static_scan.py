"""Static code scanning for the Requests-compatibility surface.

Run it directly::

    python3 -m tls_client._static_scan          # human readable
    python3 -m tls_client._static_scan --json   # machine readable

or through the test suite, which is what CI does::

    python3 -m unittest python_tests.test_requests_api_parity -v

What it checks
--------------

1. **Module parity** - every module requests ships is importable from
   tls_client and exports the same public names.
2. **Package parity** - everything requests re-exports at package level
   (functions, classes, the `codes` lookup, exception types) exists here.
3. **Signature parity** - the requests arguments of `Session.request` and of
   each verb helper keep their names, order and defaults.
4. **Three-surface parity** - the session constructor, the session properties
   and the per-request overrides all expose the same TLS knobs, so
   `session = Session()` followed by `session.<knob> = value` can never
   silently miss a knob the constructor accepts.
5. **Explicit parameters** - the documented requests arguments are named
   parameters rather than being swallowed by `**kwargs`.

The checks are AST- or signature-based and need no network and no compiled
library beyond what a normal import requires.
"""

import argparse
import ast
import importlib
import inspect
import json
import os
from typing import Any, Dict, List, Optional, Sequence, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
PACKAGE = os.path.basename(HERE)

# ---------------------------------------------------------------------------
# What requests exposes, module by module.
# ---------------------------------------------------------------------------

#: modules that must exist with the same public callables
MODULE_PARITY = {
    "api": ("request", "get", "options", "head", "post", "put", "patch", "delete"),
    "adapters": ("BaseAdapter", "HTTPAdapter"),
    "auth": ("AuthBase", "HTTPBasicAuth", "HTTPProxyAuth", "HTTPDigestAuth"),
    "certs": ("where",),
    "cookies": (
        "CookieConflictError",
        "RequestsCookieJar",
        "create_cookie",
        "cookiejar_from_dict",
        "dict_from_cookiejar",
        "merge_cookies",
        "morsel_to_cookie",
        "remove_cookie_by_name",
        "get_cookie_header",
        "extract_cookies_to_jar",
    ),
    "exceptions": (
        "RequestException",
        "InvalidJSONError",
        "JSONDecodeError",
        "HTTPError",
        "ConnectionError",
        "ProxyError",
        "SSLError",
        "Timeout",
        "ConnectTimeout",
        "ReadTimeout",
        "URLRequired",
        "TooManyRedirects",
        "MissingSchema",
        "InvalidSchema",
        "InvalidURL",
        "InvalidHeader",
        "InvalidProxyURL",
        "ChunkedEncodingError",
        "ContentDecodingError",
        "StreamConsumedError",
        "RetryError",
        "UnrewindableBodyError",
        "RequestsWarning",
        "FileModeWarning",
        "RequestsDependencyWarning",
    ),
    "hooks": ("default_hooks", "dispatch_hook"),
    "models": ("Request", "PreparedRequest", "Response"),
    "sessions": ("Session", "SessionRedirectMixin", "session"),
    "status_codes": ("codes",),
    "structures": ("CaseInsensitiveDict", "LookupDict"),
    "utils": (
        "dict_to_sequence",
        "super_len",
        "get_netrc_auth",
        "guess_filename",
        "extract_zipped_paths",
        "atomic_open",
        "from_key_val_list",
        "to_key_val_list",
        "parse_list_header",
        "parse_dict_header",
        "unquote_header_value",
        "dict_from_cookiejar",
        "add_dict_to_cookiejar",
        "get_encodings_from_content",
        "get_encoding_from_headers",
        "stream_decode_response_unicode",
        "iter_slices",
        "get_unicode_from_response",
        "unquote_unreserved",
        "requote_uri",
        "address_in_network",
        "dotted_netmask",
        "is_ipv4_address",
        "is_valid_cidr",
        "set_environ",
        "should_bypass_proxies",
        "get_environ_proxies",
        "select_proxy",
        "resolve_proxies",
        "default_user_agent",
        "default_headers",
        "parse_header_links",
        "guess_json_utf",
        "prepend_scheme_if_needed",
        "get_auth_from_url",
        "check_header_validity",
        "urldefragauth",
        "rewind_body",
    ),
    "_internal_utils": ("to_native_string", "unicode_is_ascii"),
    "compat": ("urlparse", "urlunparse", "urljoin", "urlsplit", "quote", "unquote"),
    "help": ("info", "main"),
    "packages": (),
}

#: names requests re-exports at package level
PACKAGE_EXPORTS = (
    "ConnectionError",
    "ConnectTimeout",
    "HTTPError",
    "JSONDecodeError",
    "PreparedRequest",
    "ReadTimeout",
    "Request",
    "RequestException",
    "Response",
    "Session",
    "Timeout",
    "TooManyRedirects",
    "URLRequired",
    "codes",
    "delete",
    "get",
    "head",
    "options",
    "patch",
    "post",
    "put",
    "request",
    "session",
)

#: requests arguments that must be explicit named parameters
REQUESTS_REQUEST_ARGUMENTS = (
    "params",
    "data",
    "headers",
    "cookies",
    "files",
    "auth",
    "timeout",
    "allow_redirects",
    "proxies",
    "hooks",
    "stream",
    "verify",
    "cert",
    "json",
)

#: requests attributes a Session must expose
REQUESTS_SESSION_ATTRIBUTES = (
    "adapters",
    "auth",
    "cert",
    "cookies",
    "headers",
    "hooks",
    "max_redirects",
    "params",
    "proxies",
    "stream",
    "trust_env",
    "verify",
)

#: requests methods a Session must expose
REQUESTS_SESSION_METHODS = (
    "close",
    "delete",
    "get",
    "get_adapter",
    "head",
    "merge_environment_settings",
    "mount",
    "options",
    "patch",
    "post",
    "prepare_request",
    "put",
    "request",
    "send",
)

VERB_METHODS = ("get", "options", "head", "post", "put", "patch", "delete")

VERB_METHOD_ARGUMENTS = {
    "get": ("url", "params"),
    "options": ("url",),
    "head": ("url",),
    "post": ("url", "data", "json"),
    "put": ("url", "data"),
    "patch": ("url", "data"),
    "delete": ("url",),
}

#: SessionRedirectMixin methods requests defines
REDIRECT_MIXIN_METHODS = (
    "get_redirect_target",
    "resolve_redirects",
    "rebuild_auth",
    "rebuild_proxies",
    "rebuild_method",
    "should_strip_auth",
)


def _public_names(module) -> set:
    return {name for name in dir(module) if not name.startswith("_")}


def _source_path(module_name: str) -> str:
    return os.path.join(HERE, module_name.replace(".py", "") + ".py")


def _find_function(tree, class_name: str, method_name: str):
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == method_name:
                    return item
    return None


def _class_init_params(path: str, class_name: str) -> List[str]:
    """Return the ordered parameter names of class_name.__init__ via AST."""
    with open(path, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=path)

    item = _find_function(tree, class_name, "__init__")
    if item is None:
        raise AssertionError("class %s has no __init__ in %s" % (class_name, path))
    args = item.args
    ordered = args.posonlyargs + args.args + args.kwonlyargs
    return [a.arg for a in ordered if a.arg != "self"]


def _property_names(path: str, class_name: str) -> set:
    """Return the names decorated with @property in class_name."""
    with open(path, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=path)

    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for item in node.body:
                if not isinstance(item, ast.FunctionDef):
                    continue
                for decorator in item.decorator_list:
                    if isinstance(decorator, ast.Name) and decorator.id == "property":
                        names.add(item.name)
    return names


class Report:
    """Collects problems so one run reports every drift at once."""

    def __init__(self) -> None:
        self.problems: List[str] = []
        self.checked = 0

    def check(self, condition, message: str) -> bool:
        self.checked += 1
        if not condition:
            self.problems.append(message)
        return bool(condition)

    def ok(self) -> bool:
        return not self.problems


def scan_module_parity(report: Report) -> None:
    """Every requests module is importable with the same public names."""
    for module_name, expected in sorted(MODULE_PARITY.items()):
        qualified = "%s.%s" % (PACKAGE, module_name)
        try:
            module = importlib.import_module(qualified)
        except Exception as exc:  # pragma: no cover - only on real breakage
            report.check(False, "%s failed to import: %s" % (qualified, exc))
            continue
        available = _public_names(module)
        missing = sorted(set(expected) - available)
        report.check(
            not missing, "%s is missing public names: %s" % (qualified, missing)
        )


def scan_package_exports(report: Report) -> None:
    """The package re-exports everything requests does at top level."""
    package = importlib.import_module(PACKAGE)
    for name in PACKAGE_EXPORTS:
        report.check(hasattr(package, name), "%s does not export %r" % (PACKAGE, name))
    declared = set(getattr(package, "__all__", ()))
    missing = sorted(set(PACKAGE_EXPORTS) - declared)
    report.check(not missing, "%s.__all__ is missing: %s" % (PACKAGE, missing))


def scan_request_signature(report: Report) -> None:
    """Session.request keeps the requests argument names, order and defaults."""
    from tls_client.sessions import Session

    signature = inspect.signature(Session.request)
    names = list(signature.parameters)
    for argument in REQUESTS_REQUEST_ARGUMENTS:
        report.check(
            argument in names,
            "Session.request is missing the explicit %r parameter" % argument,
        )

    for argument in ("method", "url"):
        report.check(argument in names, "Session.request is missing %r" % argument)

    # Keep the requests declaration order for the shared prefix.
    shared = [name for name in names if name in REQUESTS_REQUEST_ARGUMENTS]
    ordered = [a for a in REQUESTS_REQUEST_ARGUMENTS if a in shared]
    report.check(
        shared == ordered,
        "Session.request declares requests arguments out of order: %s" % shared,
    )

    report.check(
        signature.parameters["allow_redirects"].default is None,
        "Session.request should default allow_redirects to None (session policy)",
    )


def scan_session_attributes(report: Report) -> None:
    """Session carries every requests attribute and method."""
    from tls_client.sessions import Session

    attrs = getattr(Session, "__attrs__", ())
    for attribute in REQUESTS_SESSION_ATTRIBUTES:
        report.check(
            hasattr(Session, attribute) or attribute in attrs,
            "Session has no %r attribute" % attribute,
        )

    for method in REQUESTS_SESSION_METHODS:
        report.check(
            callable(getattr(Session, method, None)),
            "Session has no %r method" % method,
        )

    report.check(
        any(klass.__name__ == "SessionRedirectMixin" for klass in Session.__mro__),
        "Session does not inherit SessionRedirectMixin",
    )
    for method in REDIRECT_MIXIN_METHODS:
        report.check(
            callable(getattr(Session, method, None)),
            "Session has no redirect method %r" % method,
        )


def scan_verb_signatures(report: Report) -> None:
    """Every verb helper declares its requests arguments explicitly."""
    from tls_client.sessions import Session

    for verb in VERB_METHODS:
        parameters = inspect.signature(getattr(Session, verb)).parameters
        for argument in VERB_METHOD_ARGUMENTS[verb]:
            report.check(
                argument in parameters,
                "Session.%s is missing the explicit %r parameter" % (verb, argument),
            )


def scan_three_surface_parity(report: Report) -> None:
    """Constructor, properties and per-request overrides expose the same knobs."""
    from tls_client import _tls_surface
    from tls_client.sessions import REQUESTS_SESSION_EXTRAS, Session

    init_params = set(_class_init_params(_source_path("sessions"), "Session"))
    surface_path = _source_path("_tls_surface")
    properties = _property_names(surface_path, "TLSOptionsMixin")

    session_knobs = set(_tls_surface.TLS_SESSION_OPTION_NAMES)
    request_knobs = set(_tls_surface.TLS_REQUEST_OPTION_NAMES)

    report.check(
        len(session_knobs) > 40,
        "TLS_SESSION_OPTION_NAMES looks truncated (%d names)" % len(session_knobs),
    )

    missing_init = sorted(session_knobs - init_params)
    report.check(
        not missing_init,
        "Session.__init__ does not accept session knobs: %s" % missing_init,
    )

    missing_property = sorted(session_knobs - properties)
    report.check(
        not missing_property,
        "TLSOptionsMixin does not declare properties for: %s" % missing_property,
    )

    phantom = sorted(properties - session_knobs)
    report.check(
        not phantom,
        "TLSOptionsMixin declares properties with no native option: %s" % phantom,
    )

    allowed = (
        session_knobs
        | set(_tls_surface.REQUESTS_OWNED_ATTRIBUTES)
        | set(_tls_surface.SPECIAL_OPTION_NAMES)
        | set(REQUESTS_SESSION_EXTRAS)
        | {"self"}
    )
    unknown = sorted(init_params - allowed)
    report.check(
        not unknown,
        "Session.__init__ accepts parameters no surface knows about: %s" % unknown,
    )

    request_params = set(inspect.signature(Session.request).parameters)
    missing_request = sorted(
        name for name in request_knobs if name not in request_params
    )
    report.check(
        not missing_request,
        "Session.request does not declare per-request overrides: %s" % missing_request,
    )

    for verb in VERB_METHODS:
        parameters = set(inspect.signature(getattr(Session, verb)).parameters)
        skipped = sorted(
            name for name in request_knobs if name not in parameters and name != "data"
        )
        report.check(
            not skipped,
            "Session.%s does not declare per-request overrides: %s" % (verb, skipped),
        )


def scan_session_options_round_trip(report: Report) -> None:
    """Every session knob is readable and writable after construction."""
    from tls_client import _tls_surface
    from tls_client.sessions import Session

    session = Session()
    try:
        for name in _tls_surface.TLS_SESSION_OPTION_NAMES:
            try:
                value = getattr(session, name)
            except AttributeError as exc:
                report.check(False, "Session.%s is unreadable: %s" % (name, exc))
                continue
            try:
                setattr(session, name, value)
            except Exception as exc:  # pragma: no cover - only on real breakage
                report.check(False, "Session.%s is not writable: %s" % (name, exc))
    finally:
        session.close()

    defaults = _tls_surface.TLS_SESSION_OPTION_DEFAULTS
    report.check(
        set(defaults) == set(_tls_surface.TLS_SESSION_OPTION_NAMES),
        "TLS_SESSION_OPTION_DEFAULTS does not cover every session knob",
    )


#: Generated module -> (generator script, how to regenerate it)
GENERATED_FILES = (
    ("_tls_surface", "gen_requests_surface.py"),
    ("sessions", "gen_sessions.py"),
)


def scan_generated_files_current(report: Report) -> None:
    """The generated surface files match what their generators would produce."""
    tools_dir = os.path.dirname(HERE)
    for module_name, script in GENERATED_FILES:
        generator = os.path.join(tools_dir, "tools", script)
        if not os.path.exists(generator):
            report.check(False, "tools/%s is missing" % script)
            continue
        namespace: Dict[str, Any] = {
            "__name__": "_scan_generator",
            "__file__": generator,
        }
        with open(generator, "r", encoding="utf-8") as handle:
            source = handle.read()
        try:
            code = compile(source, generator, "exec")
        except SyntaxError as exc:  # pragma: no cover - only on real breakage
            report.check(False, "tools/%s does not compile: %s" % (script, exc))
            continue
        try:
            exec(code, namespace)  # executing our own build tool
            expected = namespace["build"]()
        except Exception as exc:  # pragma: no cover - only on real breakage
            report.check(False, "tools/%s failed to run: %s" % (script, exc))
            continue
        with open(_source_path(module_name), "r", encoding="utf-8") as handle:
            current = handle.read()
        report.check(
            current == expected,
            "tls_client/%s.py is stale; run tools/%s" % (module_name, script),
        )


def scan_status_codes(report: Report) -> None:
    """The status code lookup matches requests for the common names."""
    from tls_client.status_codes import codes

    expected = {
        "ok": 200,
        "created": 201,
        "no_content": 204,
        "moved_permanently": 301,
        "found": 302,
        "see_other": 303,
        "not_modified": 304,
        "temporary_redirect": 307,
        "permanent_redirect": 308,
        "bad_request": 400,
        "unauthorized": 401,
        "forbidden": 403,
        "not_found": 404,
        "method_not_allowed": 405,
        "request_timeout": 408,
        "conflict": 409,
        "im_a_teapot": 418,
        "too_many_requests": 429,
        "internal_server_error": 500,
        "bad_gateway": 502,
        "service_unavailable": 503,
        "gateway_timeout": 504,
    }
    for name, code in sorted(expected.items()):
        report.check(
            codes.get(name) == code,
            "codes.%s should be %s, got %r" % (name, code, codes.get(name)),
        )
        upper = name.upper()
        report.check(
            codes.get(upper) == code,
            "codes.%s should be %s, got %r" % (upper, code, codes.get(upper)),
        )


def scan_exception_hierarchy(report: Report) -> None:
    """Exceptions keep the requests inheritance relationships."""
    from tls_client import exceptions as exc

    relations = (
        (exc.ConnectTimeout, exc.ConnectionError),
        (exc.ConnectTimeout, exc.Timeout),
        (exc.ReadTimeout, exc.Timeout),
        (exc.ProxyError, exc.ConnectionError),
        (exc.SSLError, exc.ConnectionError),
        (exc.HTTPError, exc.RequestException),
        (exc.TooManyRedirects, exc.RequestException),
        (exc.MissingSchema, exc.RequestException),
        (exc.MissingSchema, ValueError),
        (exc.JSONDecodeError, ValueError),
        (exc.JSONDecodeError, exc.InvalidJSONError),
        (exc.FileModeWarning, DeprecationWarning),
    )
    for child, parent in relations:
        report.check(
            issubclass(child, parent),
            "%s should subclass %s" % (child.__name__, parent.__name__),
        )


SCANS = (
    ("module parity", scan_module_parity),
    ("package exports", scan_package_exports),
    ("request signature", scan_request_signature),
    ("session attributes", scan_session_attributes),
    ("verb signatures", scan_verb_signatures),
    ("three-surface parity", scan_three_surface_parity),
    ("session option round trip", scan_session_options_round_trip),
    ("generated files", scan_generated_files_current),
    ("status codes", scan_status_codes),
    ("exception hierarchy", scan_exception_hierarchy),
)


def run(scans: Sequence[Tuple[str, Any]] = SCANS) -> Report:
    """Run every scan and return the aggregated report.

    A scan that raises is recorded as a failed check rather than propagating:
    the checks import the very objects they are validating, so a missing name
    surfaces as ImportError/AttributeError.  Letting that escape would turn a
    real compatibility break into a crash with no report, and would hide every
    scan queued behind it.
    """
    report = Report()
    for name, function in scans:
        try:
            function(report)
        except Exception as exc:
            report.check(
                False,
                "scan %r raised %s: %s" % (name, type(exc).__name__, exc),
            )
    return report


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Static Requests-parity scan")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument(
        "--only",
        action="append",
        default=None,
        help="run only the named scan (repeatable)",
    )
    args = parser.parse_args(argv)

    selected = SCANS
    if args.only:
        wanted = set(args.only)
        selected = tuple(item for item in SCANS if item[0] in wanted)
        if not selected:
            parser.error("no scan matched %s" % sorted(wanted))

    report = run(selected)

    if args.json:
        print(
            json.dumps(
                {
                    "checked": report.checked,
                    "ok": report.ok(),
                    "problems": report.problems,
                },
                indent=2,
            )
        )
    else:
        for name, _ in selected:
            print("scan: %s" % name)
        print("checks: %d" % report.checked)
        if report.ok():
            print("OK - the requests compatibility surface is intact")
        else:
            for problem in report.problems:
                print("FAIL: %s" % problem)

    return 0 if report.ok() else 1


if __name__ == "__main__":
    raise SystemExit(main())
