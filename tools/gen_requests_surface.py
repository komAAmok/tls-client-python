#!/usr/bin/env python3
"""Generate tls_client/_tls_surface.py - the explicit Requests/TLS surface.

The requests-compatible facade has three surfaces that must agree:

1. Session.__init__      - session-level knobs accepted at construction
2. Session.<name>        - the same knobs, writable after construction
3. Session.request(...)  - the same knobs, overridable per request

Hand-maintaining three copies of ~60 knobs across eight verb helpers is how
signatures drift, so the literal property/method surface is generated from the
native tls_client._core.Session signature.  Only Session.__init__ and the
requests-owned attributes stay hand-written in tls_client/sessions.py.

Usage::

    python3 tools/gen_requests_surface.py            # write the file
    python3 tools/gen_requests_surface.py --check    # fail if stale (CI)
"""

import argparse
import inspect
import sys
import typing
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tls_client._core import Session as NativeSession

TARGET = ROOT / "tls_client" / "_tls_surface.py"

#: Attributes requests.Session owns; they keep requests semantics.
REQUESTS_SESSION_OWNED = (
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

#: Native knobs the facade re-interprets (documented in sessions.py).
SPECIAL_SESSION_OWNED = (
    "fingerprint",
    "follow_redirects",
    "proxy",
    "timeout",
)

#: Arguments requests Session.request and the verb helpers own.
REQUESTS_REQUEST_OWNED = (
    "allow_redirects",
    "auth",
    "body",
    "cert",
    "context",
    "cookies",
    "data",
    "files",
    "headers",
    "hooks",
    "json",
    "method",
    "params",
    "proxies",
    "stream",
    "timeout",
    "url",
    "verify",
)

VERBS = (
    ("get", "GET"),
    ("options", "OPTIONS"),
    ("head", "HEAD"),
    ("post", "POST"),
    ("put", "PUT"),
    ("patch", "PATCH"),
    ("delete", "DELETE"),
)

#: Requests arguments each verb helper forwards, in declaration order.
VERB_REQUEST_ARGS = {
    "get": ("headers", "cookies", "files", "auth", "timeout",
            "allow_redirects", "proxies", "hooks", "stream", "verify",
            "cert", "json", "context"),
    "options": ("params", "data", "headers", "cookies", "files", "auth",
                "timeout", "allow_redirects", "proxies", "hooks", "stream",
                "verify", "cert", "json", "context"),
    "head": ("params", "data", "headers", "cookies", "files", "auth",
             "timeout", "allow_redirects", "proxies", "hooks", "stream",
             "verify", "cert", "json", "context"),
    "post": ("headers", "cookies", "files", "auth", "timeout",
             "allow_redirects", "proxies", "hooks", "stream", "verify",
             "cert", "context"),
    "put": ("headers", "cookies", "files", "auth", "timeout",
            "allow_redirects", "proxies", "hooks", "stream", "verify",
            "cert", "context"),
    "patch": ("headers", "cookies", "files", "auth", "timeout",
              "allow_redirects", "proxies", "hooks", "stream", "verify",
              "cert", "context"),
    "delete": ("params", "data", "headers", "cookies", "files", "auth",
               "timeout", "allow_redirects", "proxies", "hooks", "stream",
               "verify", "cert", "json", "context"),
}

#: Parameters declared explicitly by a verb before the shared block,
#: as (name, annotation-with-default) pairs.
VERB_LEADING = {
    "get": (("params", "Optional[Any] = None"),),
    "head": (("allow_redirects", "Optional[bool] = False"),),
    "post": (("data", "Optional[Any] = None"), ("json", "Optional[Any] = None")),
    "put": (("data", "Optional[Any] = None"),),
    "patch": (("data", "Optional[Any] = None"),),
}


#: Extra keyword-only TLS knobs a verb accepts beyond its forwarded requests args.
VERB_TLS_SKIP = {"data"}


def _render_annotation(annotation) -> str:
    if annotation is inspect.Parameter.empty:
        return "Any"
    if isinstance(annotation, str):
        return annotation
    origin = typing.get_origin(annotation)
    args = typing.get_args(annotation)
    if origin is typing.Literal:
        # ClientIdentifiers is a Literal alias of the supported profile names.
        return "ClientIdentifiers"
    if origin is typing.Union:
        non_none = [a for a in args if a is not type(None)]
        inner = ", ".join(_render_annotation(a) for a in non_none)
        return "Optional[%s]" % inner if len(non_none) == 1 else "Union[%s]" % inner
    if origin is list:
        return "List[%s]" % ", ".join(_render_annotation(a) for a in args)
    if origin is dict:
        return "Dict[%s]" % ", ".join(_render_annotation(a) for a in args)
    if origin is tuple:
        return "Tuple[%s]" % ", ".join(_render_annotation(a) for a in args)
    if annotation is typing.Any:
        return "Any"
    return getattr(annotation, "__name__", repr(annotation))


def _render_default(param) -> str:
    if param.default is inspect.Parameter.empty:
        return "None"
    return repr(param.default)


def _native_params(method: str):
    signature = inspect.signature(getattr(NativeSession, method))
    return [
        (name, param)
        for name, param in signature.parameters.items()
        if name != "self" and param.kind is param.KEYWORD_ONLY
    ]


def _doc_for(name: str, fallback: str) -> str:
    native = getattr(NativeSession, name, None)
    if isinstance(native, property) and native.__doc__:
        return " ".join(native.__doc__.split())
    return fallback


def build() -> str:
    init_params = _native_params("__init__")
    exec_params = _native_params("execute_request")
    init_names = [name for name, _ in init_params]

    session_tls = [
        (name, param)
        for name, param in init_params
        if name not in REQUESTS_SESSION_OWNED and name not in SPECIAL_SESSION_OWNED
    ]

    request_tls_names = []
    for name in init_names + [n for n, _ in exec_params]:
        if name in REQUESTS_REQUEST_OWNED or name in SPECIAL_SESSION_OWNED:
            continue
        if name in ("method", "url", "body"):
            continue
        if name in request_tls_names:
            continue
        request_tls_names.append(name)

    out = []
    add = out.append
    add('"""Generated explicit surface for the requests-compatible facade.')
    add("")
    add("DO NOT EDIT BY HAND.  Regenerate with::")
    add("")
    add("    python3 tools/gen_requests_surface.py")
    add("")
    add("This module holds the mechanical part of the facade: the literal property")
    add("definitions for every session-level TLS knob, and the literal signatures of")
    add("request() plus the seven verb helpers.  Everything here is derived from the")
    add("native tls_client._core.Session signature, so IDEs, inspect and static")
    add("analysis see exactly the knobs the engine accepts.  The behavioural half")
    add("lives in tls_client/sessions.py.")
    add('"""')
    add("")
    add("from typing import Any, Dict, List, Optional, Tuple, Union  # noqa: F401")
    add("")
    add("from tls_client._core import (  # noqa: F401")
    add("    ClientIdentifiers,")
    add("    ProxyConfig,")
    add(")")
    add("")
    add("#: Every session-level TLS knob, in native declaration order.")
    add("TLS_SESSION_OPTION_NAMES = (")
    for name, _ in session_tls:
        add('    "%s",' % name)
    add(")")
    add("")
    add("#: Native default of every session-level TLS knob.")
    add("TLS_SESSION_OPTION_DEFAULTS = {")
    for name, param in session_tls:
        add('    "%s": %s,' % (name, _render_default(param)))
    add("}")
    add("")
    add("#: Every per-request TLS override accepted by request() and the verbs.")
    add("TLS_REQUEST_OPTION_NAMES = (")
    for name in request_tls_names:
        add('    "%s",' % name)
    add(")")
    add("")
    add("#: Attributes requests.Session owns; they never reach the engine directly.")
    add("REQUESTS_OWNED_ATTRIBUTES = (")
    for name in REQUESTS_SESSION_OWNED:
        add('    "%s",' % name)
    add(")")
    add("")
    add("#: Native knobs the facade re-interprets; see tls_client/sessions.py.")
    add("SPECIAL_OPTION_NAMES = (")
    for name in SPECIAL_SESSION_OWNED:
        add('    "%s",' % name)
    add(")")
    add("")
    add("")
    add("def collect_tls_options(namespace, names=TLS_REQUEST_OPTION_NAMES):")
    add('    """Return the TLS overrides actually supplied in *namespace*.')
    add("")
    add("    None means 'inherit from the session', so those entries are dropped; an")
    add("    explicit False or 0 is a real override and is kept.")
    add('    """')
    add("    options = {}")
    add("    for name in names:")
    add("        value = namespace.get(name)")
    add("        if value is not None:")
    add("            options[name] = value")
    add("    return options")
    add("")
    add("")
    add("class TLSOptionsMixin:")
    add('    """Read/write session-level TLS knobs, mirroring the native defaults."""')
    add("")
    for name, param in session_tls:
        annotation = _render_annotation(param.annotation)
        doc = _doc_for(name, annotation).replace('"', "'")
        add("    @property")
        add("    def %s(self) -> %s:" % (name, annotation))
        add('        """%s"""' % doc)
        add('        return self._get_tls_option("%s")' % name)
        add("")
        add("    @%s.setter" % name)
        add("    def %s(self, value: %s) -> None:" % (name, annotation))
        add('        self._set_tls_option("%s", value)' % name)
        add("")
    add("")
    add("class TLSVerbMixin:")
    add('    """Explicit request()/verb signatures covering every TLS override."""')
    add("")
    add("    def request(")
    add("        self,")
    add("        method: str,")
    add("        url: Any,")
    for arg in ("params", "data", "headers", "cookies", "files", "auth", "timeout"):
        add("        %s: Optional[Any] = None," % arg)
    add("        allow_redirects: Optional[bool] = None,")
    for arg in ("proxies", "hooks"):
        add("        %s: Optional[Any] = None," % arg)
    add("        stream: Optional[bool] = None,")
    for arg in ("verify", "cert", "json", "context", "body"):
        add("        %s: Optional[Any] = None," % arg)
    add("        *,")
    for name in request_tls_names:
        add("        %s: Optional[Any] = None," % name)
    add("        **kwargs: Any,")
    add("    ) -> Any:")
    add('        """Construct a Request, prepare it and send it.')
    add("")
    add("        Every requests argument is supported, plus every TLS override the")
    add("        engine understands; None means 'use the session value'.")
    add('        """')
    add("        return self._dispatch_request(")
    add("            method,")
    add("            url,")
    add("            params=params,")
    add("            data=body if body is not None else data,")
    add("            headers=headers,")
    add("            cookies=cookies,")
    add("            files=files,")
    add("            auth=auth,")
    add("            timeout=timeout,")
    add("            allow_redirects=allow_redirects,")
    add("            proxies=proxies,")
    add("            hooks=hooks,")
    add("            stream=stream,")
    add("            verify=verify,")
    add("            cert=cert,")
    add("            json=json,")
    add("            context=context,")
    add("            tls_options=collect_tls_options(locals()),")
    add("            extra_kwargs=kwargs,")
    add("        )")
    add("")
    for verb, method in VERBS:
        leading = VERB_LEADING.get(verb, ())
        forwarded = VERB_REQUEST_ARGS[verb]
        add("    def %s(" % verb)
        add("        self,")
        add("        url: Any,")
        for lead_name, lead_decl in leading:
            add("        %s: %s," % (lead_name, lead_decl))
        leading_names = {name for name, _ in leading}
        for name in forwarded:
            if name in leading_names:
                continue
            add("        %s: Optional[Any] = None," % name)
        add("        *,")
        for name in request_tls_names:
            if name in VERB_TLS_SKIP:
                continue
            add("        %s: Optional[Any] = None," % name)
        add("        **kwargs: Any,")
        add("    ) -> Any:")
        add('        """Send an HTTP %s request through this session."""' % method)
        add("        return self.request(")
        add('            "%s",' % method)
        add("            url,")
        if verb == "get":
            add("            params=params,")
        if verb in ("post", "put", "patch"):
            add("            data=data,")
        if verb == "post":
            add("            json=json,")
        for name in forwarded:
            add("            %s=%s," % (name, name))
        for name in request_tls_names:
            if name in VERB_TLS_SKIP:
                continue
            add("            %s=%s," % (name, name))
        add("            **kwargs,")
        add("        )")
        add("")
    add("")
    add("__all__ = [")
    add('    "REQUESTS_OWNED_ATTRIBUTES",')
    add('    "SPECIAL_OPTION_NAMES",')
    add('    "TLS_REQUEST_OPTION_NAMES",')
    add('    "TLS_SESSION_OPTION_DEFAULTS",')
    add('    "TLS_SESSION_OPTION_NAMES",')
    add('    "TLSOptionsMixin",')
    add('    "TLSVerbMixin",')
    add('    "collect_tls_options",')
    add("]")
    add("")
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail when stale")
    args = parser.parse_args()

    generated = build()
    if args.check:
        current = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""
        if current != generated:
            sys.stderr.write(
                "%s is stale; run python3 tools/gen_requests_surface.py\n" % TARGET
            )
            return 1
        print("%s is current" % TARGET.name)
        return 0

    TARGET.write_text(generated, encoding="utf-8")
    print("wrote %s (%d bytes)" % (TARGET, len(generated)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
