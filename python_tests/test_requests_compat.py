import json
import inspect
import unittest

import tls_client


class _NativeResponse(object):
    def __init__(self, status=200, headers=None, content=b"ok", cookies=None):
        self.status_code = status
        self.headers = headers or {"Content-Type": ["text/plain; charset=utf-8"]}
        self.content = content
        self.url = None
        self.cookies = cookies or {}
        self.used_protocol = "HTTP/2.0"

    @property
    def reason(self):
        return {200: "OK", 302: "Found", 404: "Not Found"}.get(
            self.status_code, "Unknown"
        )


class _FakeNativeSession(object):
    def __init__(self, responses=None):
        self.responses = list(responses or [_NativeResponse()])
        self.calls = []
        self.closed = False

    def execute_request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)

    def close(self):
        self.closed = True


class RequestsCompatibilityTests(unittest.TestCase):
    def test_public_session_signature_exposes_tls_options(self):
        names = set(inspect.signature(tls_client.Session).parameters)
        self.assertIn("client_identifier", names)
        self.assertIn("force_http1", names)
        self.assertIn("tcp_mss", names)
        self.assertIn("custom_tls_client", names)

    def test_unsupported_client_identifier_fails_fast(self):
        with self.assertRaises(ValueError):
            tls_client.Session(client_identifier="chrome_999", _native_session=_FakeNativeSession())

    def test_prepares_standard_requests_arguments_and_response(self):
        native = _FakeNativeSession(
            [_NativeResponse(headers={"X-Test": ["one"]}, content=b'{"ok": true}')]
        )
        session = tls_client.Session(_native_session=native)
        session.headers.update({"X-Session": "yes"})

        response = session.post(
            "https://example.test/api",
            params=[("tag", "a"), ("tag", "b")],
            json={"hello": "world"},
            auth=("user", "pass"),
            cookies={"sid": "123"},
            timeout=(1.5, 2.25),
        )

        method, url, options = native.calls[0]
        self.assertEqual(method, "POST")
        self.assertEqual(url, "https://example.test/api?tag=a&tag=b")
        self.assertEqual(json.loads(options["body"].decode("utf-8")), {"hello": "world"})
        self.assertEqual(options["headers"]["X-Session"], "yes")
        self.assertIn("Basic ", options["headers"]["Authorization"])
        self.assertIn("sid=123", options["headers"]["Cookie"])
        self.assertEqual(options["timeout_milliseconds"], 2250)
        self.assertFalse(options["follow_redirects"])

        self.assertIsInstance(response, tls_client.Response)
        self.assertEqual(response.headers["x-test"], "one")
        self.assertEqual(response.json(), {"ok": True})
        self.assertEqual(list(response.iter_content(4)), [b'{"ok', b'": t', b'rue}'])
        self.assertEqual(response.used_protocol, "HTTP/2.0")

    def test_requests_handles_redirect_history_and_cookie_jar(self):
        native = _FakeNativeSession(
            [
                _NativeResponse(
                    status=302,
                    headers={
                        "Location": ["/done"],
                        "Set-Cookie": ["token=abc; Path=/"],
                    },
                ),
                _NativeResponse(content=b"done"),
            ]
        )
        session = tls_client.Session(_native_session=native)

        response = session.get("https://example.test/start")

        self.assertEqual(response.url, "https://example.test/done")
        self.assertEqual([item.status_code for item in response.history], [302])
        self.assertEqual(session.cookies.get("token"), "abc")
        self.assertIn("token=abc", native.calls[1][2]["headers"]["Cookie"])

    def test_http_errors_use_requests_exception_types(self):
        native = _FakeNativeSession([_NativeResponse(status=404)])
        response = tls_client.Session(_native_session=native).get(
            "https://example.test/missing"
        )

        with self.assertRaises(tls_client.exceptions.HTTPError):
            response.raise_for_status()


if __name__ == "__main__":
    unittest.main()
