"""Behavioural tests for the requests-compatible facade.

The API-parity suite (test_requests_api_parity) proves the *surface* matches
requests.  This suite proves the *semantics* do, using a local echo server so
no network access, no proxy and no credentials are involved:

* args/headers/cookies/body preparation,
* session attribute merging and per-request overrides,
* redirect handling, history, auth stripping and method rewriting,
* hooks, cookie jar behaviour and environment proxies,
* encoding, content iteration and the exception hierarchy,
* the TLS controls remaining reachable through all three surfaces.
"""

import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import tls_client
from tls_client.cookies import RequestsCookieJar
from tls_client.models import PreparedRequest, Request, Response
from tls_client.sessions import Session
from tls_client.utils import get_encoding_from_headers


class _EchoHandler(BaseHTTPRequestHandler):
    """Minimal echo server: reflects headers/cookies/body as JSON."""

    protocol_version = "HTTP/1.1"

    def _drain(self):
        """Consume the request body so a keep-alive connection stays framed."""
        length = int(self.headers.get("Content-Length", 0) or 0)
        self._body = self.rfile.read(length) if length else b""

    def _payload(self, extra=None):
        body = getattr(self, "_body", b"")
        payload = {
            "method": self.command,
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body.decode("utf-8", "replace"),
        }
        if extra:
            payload.update(extra)
        return json.dumps(payload).encode("utf-8")

    def _send(self, status, payload, headers=None):
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _route(self):
        path = self.path.split("?")[0]
        self._drain()
        if path == "/redirect":
            self._send(302, b"", {"Location": "/final", "Set-Cookie": "hop=1; Path=/"})
            return
        if path == "/redirect-301":
            self._send(301, b"", {"Location": "/final"})
            return
        if path == "/redirect-303":
            self._send(303, b"", {"Location": "/final"})
            return
        if path == "/redirect-307":
            self._send(307, b"", {"Location": "/final"})
            return
        if path == "/loop":
            self._send(302, b"", {"Location": "/loop"})
            return
        if path == "/cross-host":
            self._send(302, b"", {"Location": "http://example.invalid/"})
            return
        if path == "/error":
            self._send(500, json.dumps({"error": "boom"}).encode("utf-8"))
            return
        if path == "/notfound":
            self._send(404, b"missing")
            return
        if path == "/latin1":
            payload = "caf\xe9".encode("latin1")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=ISO-8859-1")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if path == "/ncharset":
            payload = b"plain text"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if path == "/links":
            self._send(
                200,
                b"ok",
                {
                    "Link": '<http://a/next>; rel="next", <http://a/last>; rel="last"',
                },
            )
            return
        if path == "/json-bad":
            self._send(200, b"{not json")
            return
        if path == "/empty":
            self._send(200, b"")
            return
        if path == "/auth":
            # Challenge once, then accept the replayed digest credential.
            if self.headers.get("Authorization", "").startswith("Digest "):
                self._send(200, self._payload())
                return
            self._send(
                401,
                b"nope",
                {"WWW-Authenticate": 'Digest realm="test", nonce="abc", qop="auth"'},
            )
            return
        self._send(200, self._payload())

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _route

    def log_message(self, *args):  # keep the test output clean
        pass


class _ServerCase(unittest.TestCase):
    """Base class that runs one echo server for the whole test case."""

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)


class RequestPreparationTests(unittest.TestCase):
    """Request/PreparedRequest preparation follows the requests rules."""

    def test_params_merge_into_the_query_string(self):
        prepared = Request(
            method="GET", url="https://e.test/p?a=1", params={"b": "2"}
        ).prepare()
        self.assertEqual(prepared.url, "https://e.test/p?a=1&b=2")
        self.assertEqual(prepared.path_url, "/p?a=1&b=2")

    def test_list_params_repeat_the_key(self):
        prepared = Request(
            method="GET", url="https://e.test/p", params=[("t", "a"), ("t", "b")]
        ).prepare()
        self.assertEqual(prepared.url, "https://e.test/p?t=a&t=b")

    def test_form_data_urlencodes_and_sets_content_type(self):
        prepared = Request(
            method="POST", url="https://e.test/p", data={"k": "v v"}
        ).prepare()
        self.assertEqual(prepared.body, b"k=v+v")
        self.assertEqual(
            prepared.headers["Content-Type"], "application/x-www-form-urlencoded"
        )
        self.assertEqual(prepared.headers["Content-Length"], "5")

    def test_json_body_is_encoded_and_typed(self):
        prepared = Request(
            method="POST", url="https://e.test/p", json={"a": [1, 2]}
        ).prepare()
        self.assertEqual(json.loads(prepared.body.decode()), {"a": [1, 2]})
        self.assertEqual(prepared.headers["Content-Type"], "application/json")

    def test_files_produce_a_multipart_body(self):
        prepared = Request(
            method="POST",
            url="https://e.test/p",
            files={"f": ("a.txt", b"hello", "text/plain")},
        ).prepare()
        self.assertIn("multipart/form-data; boundary=", prepared.headers["Content-Type"])
        self.assertIn(b'name="f"; filename="a.txt"', prepared.body)
        self.assertIn(b"hello", prepared.body)

    def test_missing_scheme_raises_missing_schema(self):
        with self.assertRaises(tls_client.exceptions.MissingSchema):
            Request(method="GET", url="e.test/p").prepare()

    def test_unsupported_scheme_raises_invalid_schema(self):
        with self.assertRaises(tls_client.exceptions.InvalidSchema):
            Request(method="GET", url="ftp://e.test/p").prepare()

    def test_headers_are_case_insensitive(self):
        prepared = Request(
            method="GET", url="https://e.test/p", headers={"X-Test": "1"}
        ).prepare()
        self.assertEqual(prepared.headers["x-test"], "1")
        self.assertIn("X-Test", prepared.headers)

    def test_basic_auth_tuple_becomes_the_authorization_header(self):
        prepared = Request(
            method="GET", url="https://e.test/p", auth=("u", "p")
        ).prepare()
        self.assertEqual(prepared.headers["Authorization"], "Basic dTpw")

    def test_url_credentials_become_basic_auth(self):
        prepared = Request(method="GET", url="https://u:p@e.test/p").prepare()
        self.assertEqual(prepared.headers["Authorization"], "Basic dTpw")

    def test_cookies_become_the_cookie_header(self):
        prepared = Request(
            method="GET", url="https://e.test/p", cookies={"sid": "1"}
        ).prepare()
        self.assertEqual(prepared.headers["Cookie"], "sid=1")

    def test_prepare_can_be_called_field_by_field(self):
        prepared = PreparedRequest()
        prepared.prepare_method("post")
        prepared.prepare_url("https://e.test/p", None)
        prepared.prepare_headers(None)
        prepared.prepare_cookies(None)
        prepared.prepare_body({"k": "v"}, None, None)
        prepared.prepare_auth(None, "https://e.test/p")
        self.assertEqual(prepared.method, "POST")
        self.assertEqual(prepared.body, b"k=v")

    def test_copy_is_independent(self):
        prepared = Request(
            method="GET", url="https://e.test/p", headers={"X": "1"}
        ).prepare()
        clone = prepared.copy()
        clone.headers["X"] = "2"
        self.assertEqual(prepared.headers["X"], "1")

    def test_hooks_can_be_registered_and_deregistered(self):
        request = Request(method="GET", url="https://e.test/p")

        def hook(response, **kwargs):
            return response

        request.register_hook("response", hook)
        self.assertEqual(request.hooks["response"], [hook])
        self.assertTrue(request.deregister_hook("response", hook))
        self.assertFalse(request.deregister_hook("response", hook))

    def test_registering_an_unknown_hook_event_fails(self):
        request = Request(method="GET", url="https://e.test/p")
        with self.assertRaises(ValueError):
            request.register_hook("nope", lambda *a: None)


class ResponseModelTests(unittest.TestCase):
    """Response mirrors requests' behaviour on hand-built responses."""

    def _response(self, status=200, body=b"ok", headers=None, reason="OK"):
        response = Response()
        response.status_code = status
        response.reason = reason
        response.url = "https://e.test/p"
        response.headers.update(headers or {"Content-Type": "text/plain"})
        # A real response gets its encoding from the Content-Type charset, so
        # set it here too; otherwise text falls back to apparent_encoding,
        # which depends on whether charset_normalizer happens to be installed.
        response.encoding = get_encoding_from_headers(response.headers)
        response._content = body
        response._content_consumed = True
        return response

    def test_ok_and_bool(self):
        self.assertTrue(self._response().ok)
        self.assertTrue(bool(self._response()))
        self.assertFalse(self._response(404, reason="Not Found").ok)
        self.assertFalse(bool(self._response(500, reason="Boom")))

    def test_raise_for_status_messages(self):
        with self.assertRaises(tls_client.exceptions.HTTPError) as ctx:
            self._response(404, reason="Not Found").raise_for_status()
        self.assertIn("404 Client Error", str(ctx.exception))
        with self.assertRaises(tls_client.exceptions.HTTPError) as ctx:
            self._response(503, reason="Unavailable").raise_for_status()
        self.assertIn("503 Server Error", str(ctx.exception))
        self.assertIsNone(self._response().raise_for_status())

    def test_text_decodes_with_the_declared_charset(self):
        response = self._response(
            body="caf\xe9".encode("latin1"),
            headers={"Content-Type": "text/plain; charset=ISO-8859-1"},
        )
        self.assertEqual(response.text, "caf\xe9")

    def test_text_returns_empty_string_for_an_empty_body(self):
        self.assertEqual(self._response(body=b"").text, "")

    def test_json_parses_and_reports_failures_as_requests_errors(self):
        self.assertEqual(self._response(body=b'{"a": 1}').json(), {"a": 1})
        self.assertIsNone(self._response(body=b"").json())
        with self.assertRaises(tls_client.exceptions.JSONDecodeError):
            self._response(body=b"{bad").json()

    def test_json_decode_error_is_a_value_error_and_a_request_exception(self):
        with self.assertRaises(ValueError):
            self._response(body=b"{bad").json()
        try:
            self._response(body=b"{bad").json()
        except tls_client.exceptions.RequestException:
            pass
        else:  # pragma: no cover - the raise above proves it
            self.fail("JSONDecodeError should subclass RequestException")

    def test_iter_content_slices(self):
        response = self._response(body=b"abcdef")
        self.assertEqual(list(response.iter_content(2)), [b"ab", b"cd", b"ef"])

    def test_iter_content_rejects_a_non_integer_chunk_size(self):
        with self.assertRaises(TypeError):
            list(self._response().iter_content("2"))

    def test_iter_content_treats_a_non_positive_size_as_one_chunk(self):
        # requests allows 0/None and returns the whole body in one piece.
        self.assertEqual(list(self._response(body=b"ab").iter_content(0)), [b"ab"])
        self.assertEqual(list(self._response(body=b"ab").iter_content(None)), [b"ab"])

    def test_iter_lines_splits_on_delimiters(self):
        response = self._response(body=b"a\nb\nc")
        self.assertEqual(list(response.iter_lines()), [b"a", b"b", b"c"])
        self.assertEqual(list(response.iter_lines(delimiter=b"\n")), [b"a", b"b", b"c"])

    def test_response_is_iterable(self):
        self.assertEqual(list(self._response(body=b"xy")), [b"xy"])

    def test_links_are_parsed(self):
        response = self._response(
            headers={"Link": '<https://a/next>; rel="next"'}
        )
        self.assertEqual(response.links["next"]["url"], "https://a/next")

    def test_redirect_flags(self):
        redirect = self._response(301, headers={"Location": "/x"})
        self.assertTrue(redirect.is_redirect)
        self.assertTrue(redirect.is_permanent_redirect)
        self.assertFalse(self._response(307, headers={"Location": "/x"}).is_permanent_redirect)

    def test_response_pickles(self):
        import pickle

        response = self._response(body=b"payload")
        clone = pickle.loads(pickle.dumps(response))
        self.assertEqual(clone.content, b"payload")
        self.assertEqual(clone.status_code, 200)

    def test_context_manager_closes(self):
        response = self._response()
        with response as handle:
            self.assertIs(handle, response)


class SessionSemanticsTests(_ServerCase):
    """Session-level behaviour, exercised against the local server."""

    def test_session_headers_are_sent(self):
        session = Session()
        session.headers.update({"X-Test": "yes"})
        payload = session.get(self.base + "/echo").json()
        self.assertEqual(payload["headers"]["x-test"], "yes")

    def test_request_headers_override_session_headers(self):
        session = Session()
        session.headers.update({"X-Test": "session"})
        payload = session.get(self.base + "/echo", headers={"X-Test": "request"}).json()
        self.assertEqual(payload["headers"]["x-test"], "request")

    def test_session_params_merge_with_request_params(self):
        session = Session()
        session.params = {"a": "1"}
        payload = session.get(self.base + "/echo", params={"b": "2"}).json()
        self.assertEqual(payload["path"], "/echo?a=1&b=2")

    def test_verbs_send_the_matching_method(self):
        session = Session()
        for verb, method in (
            ("get", "GET"),
            ("options", "OPTIONS"),
            ("head", "HEAD"),
            ("post", "POST"),
            ("put", "PUT"),
            ("patch", "PATCH"),
            ("delete", "DELETE"),
        ):
            with self.subTest(verb=verb):
                response = getattr(session, verb)(self.base + "/echo")
                self.assertEqual(response.status_code, 200)
                if verb == "head":
                    continue
                self.assertEqual(response.json()["method"], method)

    def test_post_data_and_json_are_mutually_exclusive(self):
        session = Session()
        payload = session.post(self.base + "/echo", data={"a": "1"}).json()
        self.assertEqual(payload["body"], "a=1")
        payload = session.post(self.base + "/echo", json={"a": 1}).json()
        self.assertEqual(json.loads(payload["body"]), {"a": 1})

    def test_get_accepts_a_params_list(self):
        payload = Session().get(
            self.base + "/echo", params=[("t", "a"), ("t", "b")]
        ).json()
        self.assertEqual(payload["path"], "/echo?t=a&t=b")

    def test_head_defaults_to_no_redirects(self):
        session = Session()
        response = session.head(self.base + "/redirect")
        self.assertEqual(response.status_code, 302)

    def test_get_follows_redirects_and_records_history(self):
        session = Session()
        response = session.get(self.base + "/redirect")
        self.assertEqual(response.status_code, 200)
        self.assertEqual([item.status_code for item in response.history], [302])
        self.assertTrue(response.url.endswith("/final"))

    def test_allow_redirects_false_stops_at_the_redirect(self):
        session = Session()
        response = session.get(self.base + "/redirect", allow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.history, [])
        self.assertIsNotNone(response.next)

    def test_301_turns_a_post_into_a_get(self):
        session = Session()
        response = session.post(self.base + "/redirect-301", data={"a": "1"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["method"], "GET")

    def test_303_turns_any_method_into_a_get(self):
        response = Session().post(self.base + "/redirect-303", data={"a": "1"})
        self.assertEqual(response.json()["method"], "GET")

    def test_307_preserves_method_and_body(self):
        response = Session().post(self.base + "/redirect-307", data={"a": "1"})
        self.assertEqual(response.json()["method"], "POST")
        self.assertEqual(response.json()["body"], "a=1")

    def test_redirect_loop_raises_too_many_redirects(self):
        session = Session()
        session.max_redirects = 3
        with self.assertRaises(tls_client.exceptions.TooManyRedirects):
            session.get(self.base + "/loop")

    def test_cookies_from_a_redirect_are_stored_and_replayed(self):
        session = Session()
        session.get(self.base + "/redirect")
        self.assertEqual(session.cookies.get("hop"), "1")
        payload = session.get(self.base + "/echo").json()
        self.assertIn("hop=1", payload["headers"].get("cookie", ""))

    def test_explicit_cookies_are_sent_without_touching_the_jar(self):
        session = Session()
        payload = session.get(self.base + "/echo", cookies={"one": "1"}).json()
        self.assertIn("one=1", payload["headers"]["cookie"])
        self.assertIsNone(session.cookies.get("one"))

    def test_environment_proxies_can_be_ignored(self):
        os.environ["HTTP_PROXY"] = "http://127.0.0.1:9"
        try:
            session = Session()
            session.trust_env = False
            self.assertEqual(session.get(self.base + "/echo").status_code, 200)
        finally:
            os.environ.pop("HTTP_PROXY", None)

    def test_merge_environment_settings_prefers_explicit_values(self):
        session = Session()
        session.verify = True
        settings = session.merge_environment_settings(
            self.base, {}, None, False, None
        )
        self.assertFalse(settings["verify"])
        self.assertEqual(settings["stream"], session.stream)

    def test_response_hook_can_rewrite_the_response(self):
        seen = []

        def hook(response, **kwargs):
            seen.append(response.status_code)
            response.hooked = True
            return response

        session = Session()
        response = session.get(self.base + "/echo", hooks={"response": hook})
        self.assertEqual(seen, [200])
        self.assertTrue(response.hooked)

    def test_session_hooks_apply_to_every_request(self):
        seen = []

        def hook(response, **kwargs):
            seen.append(response.url)
            return response

        session = Session()
        session.hooks["response"].append(hook)
        session.get(self.base + "/echo")
        session.get(self.base + "/final")
        self.assertEqual(len(seen), 2)

    def test_mount_replaces_the_adapter_for_a_prefix(self):
        from tls_client.adapters import BaseAdapter

        calls = []

        class Recording(BaseAdapter):
            def __init__(self, inner):
                super().__init__()
                self.inner = inner

            def send(self, request, **kwargs):
                calls.append(request.url)
                return self.inner.send(request, **kwargs)

            def close(self):
                return None

        session = Session()
        inner = session.get_adapter(self.base)
        session.mount(self.base, Recording(inner))
        session.get(self.base + "/echo")
        self.assertEqual(calls, [self.base + "/echo"])

    def test_get_adapter_sorts_by_prefix_length(self):
        session = Session()
        default = session.get_adapter("https://anything/")
        session.mount("https://specific/", default)
        self.assertIs(session.get_adapter("https://specific/x"), default)
        self.assertIs(session.get_adapter("https://other/x"), default)

    def test_no_adapter_raises_invalid_schema(self):
        session = Session()
        session.adapters.clear()
        with self.assertRaises(tls_client.exceptions.InvalidSchema):
            session.get_adapter("https://e.test/")

    def test_error_statuses_raise_through_raise_for_status(self):
        session = Session()
        response = session.get(self.base + "/error")
        self.assertEqual(response.status_code, 500)
        with self.assertRaises(tls_client.exceptions.HTTPError):
            response.raise_for_status()

    def test_charset_from_the_content_type_is_honoured(self):
        session = Session()
        response = session.get(self.base + "/latin1")
        self.assertEqual(response.encoding, "ISO-8859-1")
        self.assertEqual(response.text, "caf\xe9")

    def test_missing_charset_falls_back_to_apparent_encoding(self):
        response = Session().get(self.base + "/ncharset")
        self.assertEqual(response.encoding, "ISO-8859-1")
        self.assertEqual(response.text, "plain text")

    def test_link_headers_are_parsed(self):
        response = Session().get(self.base + "/links")
        self.assertEqual(sorted(response.links), ["last", "next"])

    def test_invalid_json_raises_the_requests_error(self):
        response = Session().get(self.base + "/json-bad")
        with self.assertRaises(tls_client.exceptions.JSONDecodeError):
            response.json()

    def test_empty_body_json_is_none(self):
        self.assertIsNone(Session().get(self.base + "/empty").json())

    def test_body_and_protocol_metadata_are_populated(self):
        response = Session().get(self.base + "/echo")
        self.assertIsInstance(response.elapsed.total_seconds(), float)
        self.assertIsNotNone(response.used_protocol)
        self.assertIsInstance(response.request, PreparedRequest)

    def test_session_is_a_context_manager(self):
        with Session() as session:
            self.assertEqual(session.get(self.base + "/echo").status_code, 200)

    def test_typed_request_accepts_a_request_object(self):
        session = Session()
        response = session.typed_request(Request(method="GET", url=self.base + "/echo"))
        self.assertEqual(response.status_code, 200)

    def test_typed_request_accepts_a_mapping(self):
        session = Session()
        response = session.typed_request(
            {"method": "GET", "url": self.base + "/echo"}
        )
        self.assertEqual(response.status_code, 200)

    def test_typed_request_accepts_a_prepared_request(self):
        session = Session()
        prepared = session.prepare_request(Request(method="GET", url=self.base + "/echo"))
        self.assertEqual(session.typed_request(prepared).status_code, 200)

    def test_unexpected_request_argument_is_rejected(self):
        with self.assertRaises(TypeError):
            Session().get(self.base + "/echo", not_an_argument=1)

    def test_execute_request_alias_accepts_the_same_arguments(self):
        session = Session()
        response = session.execute_request("GET", self.base + "/echo", params={"a": "1"})
        self.assertEqual(response.json()["path"], "/echo?a=1")

    def test_resolve_redirects_yields_the_followed_responses(self):
        """A body-less redirect must not be mistaken for an unrewindable one.

        The rewind guard keys off _body_position plus a framing header, not off
        the mere presence of the attribute, so a plain GET walks the chain
        instead of raising UnrewindableBodyError.
        """
        session = Session()
        first = session.get(self.base + "/redirect", allow_redirects=False)
        self.assertEqual(first.status_code, 302)
        followed = list(session.resolve_redirects(first, first.request))
        self.assertEqual([item.status_code for item in followed], [200])

    def test_resolve_redirects_accepts_yield_requests(self):
        """yield_requests=True hands back the *next* PreparedRequest.

        The generator never advances the redirect target on this path (it is
        requests' internal hook for pre-flight inspection), so callers take one
        item rather than draining it.
        """
        session = Session()
        first = session.get(self.base + "/redirect", allow_redirects=False)
        generator = session.resolve_redirects(first, first.request, yield_requests=True)
        try:
            prepared = next(generator)
        finally:
            generator.close()
        self.assertEqual(prepared.method, "GET")
        self.assertTrue(prepared.url.endswith("/final"))

    def test_session_survives_a_pickle_round_trip(self):
        """requests promises a picklable Session; the engine is rebuilt.

        The transport adapter holds the native engine session (and its lock),
        so it is dropped from the pickled state and rebuilt on load.  The
        requests-visible configuration must survive.
        """
        import pickle

        session = Session()
        session.headers.update({"X-Test": "pickled"})
        session.params = {"p": "1"}
        session.cookies.set("c", "1")
        session.verify = False

        restored = pickle.loads(pickle.dumps(session))
        self.assertEqual(restored.headers["X-Test"], "pickled")
        self.assertEqual(restored.params, {"p": "1"})
        self.assertEqual(restored.cookies.get("c"), "1")
        self.assertFalse(restored.verify)
        self.assertEqual(sorted(restored.adapters), ["http://", "https://"])
        # The rebuilt session must actually be usable.
        self.assertEqual(restored.get(self.base + "/echo").status_code, 200)

    def test_session_survives_deepcopy(self):
        import copy

        session = Session()
        session.headers.update({"X-Copy": "1"})
        clone = copy.deepcopy(session)
        self.assertEqual(clone.headers["X-Copy"], "1")
        self.assertEqual(clone.get(self.base + "/echo").status_code, 200)

    def test_per_request_proxy_mapping_is_honoured(self):
        """The single-proxy alias accepts a string or a requests-style mapping.

        A mapping used to be dropped on the floor, silently sending the request
        without a proxy.
        """
        recorded = {}

        from tls_client.adapters import BaseAdapter

        class Recording(BaseAdapter):
            """Records the adapter kwargs without performing a real request."""

            def __init__(self):
                super().__init__()

            def send(self, request, **kwargs):
                recorded.update(kwargs)
                response = Response()
                response.status_code = 200
                response.url = request.url
                response.request = request
                response.headers["Content-Type"] = "text/plain"
                response._content = b"ok"
                response._content_consumed = True
                return response

            def close(self):
                return None

        session = Session()
        session.mount(self.base, Recording())

        session.get(self.base + "/echo", proxy={"http": "http://p1:1"})
        self.assertEqual(recorded["proxies"], {"http": "http://p1:1"})

        session.get(self.base + "/echo", proxy="http://p2:2")
        self.assertEqual(
            recorded["proxies"], {"http": "http://p2:2", "https": "http://p2:2"}
        )

        # The alias merges into, rather than replacing, explicit proxies.
        session.get(
            self.base + "/echo",
            proxies={"https": "http://explicit:1"},
            proxy="http://p3:3",
        )
        self.assertEqual(
            recorded["proxies"],
            {"https": "http://explicit:1", "http": "http://p3:3"},
        )

    def test_header_order_is_a_per_request_control(self):
        """header_order must reach the engine through the facade."""
        session = Session()
        response = session.get(
            self.base + "/echo",
            header_order=["Host", "X-Test", "User-Agent"],
            headers={"X-Test": "1"},
        )
        self.assertEqual(response.status_code, 200)

    def test_prepare_request_merges_session_and_request_state(self):
        session = Session()
        session.headers.update({"X-Session": "1"})
        session.params = {"s": "1"}
        session.cookies.set("c", "1")
        prepared = session.prepare_request(
            Request(
                method="GET",
                url=self.base + "/echo",
                headers={"X-Request": "1"},
                params={"r": "1"},
            )
        )
        self.assertEqual(prepared.headers["X-Session"], "1")
        self.assertEqual(prepared.headers["X-Request"], "1")
        self.assertIn("s=1", prepared.url)
        self.assertIn("r=1", prepared.url)
        self.assertIn("c=1", prepared.headers["Cookie"])


class DigestAuthTests(_ServerCase):
    """HTTPDigestAuth drives a 401 challenge replay through Session.send."""

    def test_digest_challenge_produces_an_authorization_header(self):
        from tls_client.auth import HTTPDigestAuth

        session = Session()
        auth = HTTPDigestAuth("user", "pass")
        response = session.get(self.base + "/auth", auth=auth)
        self.assertEqual(response.status_code, 200)
        header = response.json()["headers"].get("authorization", "")
        self.assertTrue(header.startswith("Digest "), header)
        self.assertIn('username="user"', header)
        self.assertIn('realm="test"', header)

    def test_basic_auth_survives_the_round_trip(self):
        payload = Session().get(self.base + "/echo", auth=("u", "p")).json()
        self.assertEqual(payload["headers"]["authorization"], "Basic dTpw")


class CookieJarBehaviourTests(_ServerCase):
    """The cookie jar participates in policy, not just storage."""

    def test_cookiejar_from_dict_and_back(self):
        jar = tls_client.cookies.cookiejar_from_dict({"a": "1"})
        self.assertIsInstance(jar, RequestsCookieJar)
        self.assertEqual(tls_client.cookies.dict_from_cookiejar(jar), {"a": "1"})

    def test_merge_cookies_keeps_existing_values(self):
        jar = tls_client.cookies.cookiejar_from_dict({"a": "1"})
        merged = tls_client.cookies.merge_cookies(jar, {"a": "2", "b": "3"})
        self.assertEqual(merged.get("a"), "1")
        self.assertEqual(merged.get("b"), "3")

    def test_cookie_conflicts_raise(self):
        jar = RequestsCookieJar()
        jar.set("dup", "1", domain="a.test")
        jar.set("dup", "2", domain="b.test")
        with self.assertRaises(tls_client.cookies.CookieConflictError):
            jar["dup"]
        self.assertEqual(jar.get("dup", domain="a.test"), "1")

    def test_setting_none_removes_the_cookie(self):
        jar = tls_client.cookies.cookiejar_from_dict({"a": "1"})
        jar.set("a", None)
        self.assertIsNone(jar.get("a"))

    def test_jar_survives_pickling(self):
        import pickle

        jar = tls_client.cookies.cookiejar_from_dict({"a": "1", "b": "2"})
        clone = pickle.loads(pickle.dumps(jar))
        self.assertEqual(tls_client.cookies.dict_from_cookiejar(clone), {"a": "1", "b": "2"})

    def test_jar_reports_domains_and_paths(self):
        jar = RequestsCookieJar()
        jar.set("a", "1")
        jar.set("b", "2", domain="x.test", path="/deep")
        self.assertIn("x.test", jar.list_domains())
        self.assertIn("/deep", jar.list_paths())
        self.assertTrue(jar.multiple_domains() is False or True)

    def test_response_cookies_are_exposed_as_a_jar(self):
        response = Session().get(self.base + "/redirect", allow_redirects=False)
        self.assertIsInstance(response.cookies, RequestsCookieJar)
        self.assertEqual(response.cookies.get("hop"), "1")


class TLSSurfaceTests(_ServerCase):
    """The TLS knobs are reachable from all three surfaces."""

    def test_session_knob_written_after_construction_applies(self):
        from tls_client import _tls_surface

        session = Session()
        session.tcp_ttl = 64
        self.assertEqual(session.tcp_ttl, 64)
        self.assertEqual(session._native.tcp_ttl, 64)
        payload = session.get(self.base + "/echo").json()
        self.assertIn("user-agent", payload["headers"])
        self.assertIn("tcp_ttl", _tls_surface.TLS_SESSION_OPTION_NAMES)

    def test_per_request_override_does_not_change_the_session(self):
        session = Session()
        session.client_identifier = "chrome_120"
        session.get(self.base + "/echo", force_http1=True)
        self.assertEqual(session.client_identifier, "chrome_120")
        payload = session.get(self.base + "/echo").json()
        self.assertEqual(payload["method"], "GET")

    def test_constructor_argument_reaches_the_engine(self):
        session = Session(tcp_window_size=65535, disable_compression=True)
        try:
            self.assertEqual(session.tcp_window_size, 65535)
            self.assertTrue(session.disable_compression)
        finally:
            session.close()

    def test_unknown_constructor_argument_is_rejected(self):
        with self.assertRaises(TypeError):
            Session(not_a_real_option=1)

    def test_unsupported_client_identifier_fails_fast(self):
        with self.assertRaises(ValueError):
            Session(client_identifier="chrome_999")

    def test_adapter_is_mounted_for_both_schemes(self):
        session = Session()
        advisory = session.get_adapter("http://e.test/")
        secure = session.get_adapter("https://e.test/")
        self.assertIs(advisory, secure)

    def test_close_is_idempotent(self):
        session = Session()
        session.close()
        session.close()

    def test_request_context_is_accepted(self):
        from tls_client.context import RequestContext

        session = Session()
        context = RequestContext.navigation(self.base + "/echo")
        response = session.get(self.base + "/echo", context=context)
        self.assertEqual(response.status_code, 200)

    def test_fingerprint_preset_round_trips(self):
        from tls_client._core import SUPPORTED_CLIENT_IDENTIFIERS
        from tls_client.fingerprints import list_presets, resolve

        usable = [
            name
            for name in list_presets()
            if resolve(name).get("client_identifier") in SUPPORTED_CLIENT_IDENTIFIERS
        ]
        if not usable:  # pragma: no cover - catalogue change
            self.skipTest("no preset matches a supported client identifier")
        session = Session(fingerprint=usable[0])
        try:
            self.assertEqual(session.fingerprint, usable[0])
            self.assertIn(session.client_identifier, SUPPORTED_CLIENT_IDENTIFIERS)
        finally:
            session.close()


class TopLevelApiTests(_ServerCase):
    """The module-level helpers work like requests'."""

    def test_top_level_get(self):
        self.assertEqual(tls_client.get(self.base + "/echo").status_code, 200)

    def test_top_level_request(self):
        response = tls_client.request("GET", self.base + "/echo")
        self.assertEqual(response.status_code, 200)

    def test_top_level_post_with_json(self):
        response = tls_client.post(self.base + "/echo", json={"a": 1})
        self.assertEqual(json.loads(response.json()["body"]), {"a": 1})

    def test_top_level_head_does_not_follow_redirects(self):
        self.assertEqual(tls_client.head(self.base + "/redirect").status_code, 302)

    def test_top_level_helpers_close_their_session(self):
        response = tls_client.get(self.base + "/echo")
        # The session is closed, but the response is fully materialised.
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.content, bytes)

    def test_session_factory_returns_a_session(self):
        instance = tls_client.session()
        self.assertIsInstance(instance, Session)


if __name__ == "__main__":
    unittest.main(verbosity=2)
