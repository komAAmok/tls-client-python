# Requests API surface — summary & compatibility contract

Reference: `psf/requests` (checkout at `../requests`, `src/requests/`), plus the
`requests` release installed in the test environment.

This document is the checklist this project implements. Every module, class and
function named below is reachable from `tls_client` with the same name, the same
call signature and the same observable behaviour, so existing `requests` code
runs after a single `import tls_client as requests`.

## 1. Package level (`requests/__init__.py`)

| Export | Kind | Provided by |
| --- | --- | --- |
| `request, get, options, head, post, put, patch, delete` | functions | `tls_client.api` |
| `Session`, `session` | class / factory | `tls_client.sessions` |
| `Request`, `PreparedRequest`, `Response` | models | `tls_client.models` |
| `codes` | status lookup | `tls_client.status_codes` |
| `packages`, `utils` | modules | `tls_client.packages`, `tls_client.utils` |
| `ConnectionError, ConnectTimeout, HTTPError, JSONDecodeError, ReadTimeout, RequestException, Timeout, TooManyRedirects, URLRequired` | exceptions | `tls_client.exceptions` |
| `__version__, __title__, __author__, __license__, __copyright__, __build__, __cake__, __description__, __url__, __author_email__` | metadata | `tls_client.__version__` |

## 2. `requests.api`

`request(method, url, **kwargs)` and the seven verb helpers
`get/options/head/post/put/patch/delete`. `head` defaults
`allow_redirects=False`; every other verb defaults `True`.

## 3. `requests.sessions`

* `Session` — attributes `headers, auth, proxies, hooks, params, stream, verify,
  cert, max_redirects, trust_env, cookies, adapters, __attrs__`; methods
  `__enter__, __exit__, prepare_request, request, get, options, head, post, put,
  patch, delete, send, merge_environment_settings, get_adapter, mount, close,
  __getstate__, __setstate__`.
* `SessionRedirectMixin` — `get_redirect_target, should_strip_auth,
  resolve_redirects, rebuild_auth, rebuild_proxies, rebuild_method`.
* `session()` factory, `merge_setting()`, `merge_hooks()`.
* `DEFAULT_REDIRECT_LIMIT = 30`.

## 4. `requests.models`

* `Request` (`prepare`, `register_hook`, `deregister_hook`, `path_url`),
  `RequestEncodingMixin`, `RequestHooksMixin`.
* `PreparedRequest` (`prepare`, `copy`, `prepare_method`, `prepare_url`,
  `prepare_headers`, `prepare_cookies`, `prepare_body`,
  `prepare_content_length`, `prepare_auth`, `prepare_hooks`).
* `Response` (`content`, `text`, `json`, `ok`, `is_redirect`,
  `is_permanent_redirect`, `next`, `links`, `apparent_encoding`,
  `iter_content`, `iter_lines`, `raise_for_status`, `close`,
  `__enter__`, `__exit__`, `__bool__`, `__nonzero__`, `__iter__`).
* Constants `REDIRECT_STATI`, `DEFAULT_REDIRECT_LIMIT`, `CONTENT_CHUNK_SIZE`,
  `ITER_CHUNK_SIZE`.

## 5. `requests.adapters`

`BaseAdapter` (`send`, `close`), `HTTPAdapter` (the TLS-client transport:
`send`, `close`, `mount`-compatible), `DEFAULT_POOLBLOCK`,
`DEFAULT_POOLSIZE`, `DEFAULT_RETRIES`.

## 6. `requests.auth`

`AuthBase`, `HTTPBasicAuth`, `HTTPProxyAuth`, `HTTPDigestAuth`
(including the 401 challenge replay that `Session.send` drives).

## 7. `requests.cookies`

`RequestsCookieJar` (dict interface + `get/set/list_domains/list_paths/
multiple_domains/get_dict/items/keys/values/iteritems/iterkeys/itervalues`),
`CookieConflictError`, `create_cookie`, `morsel_to_cookie`,
`cookiejar_from_dict`, `dict_from_cookiejar`, `add_dict_to_cookiejar`,
`merge_cookies`, `extract_cookies_to_jar`, `get_cookie_header`,
`remove_cookie_by_name`, `MockRequest`, `MockResponse`, `CookieJar`.

## 8. `requests.structures`

`CaseInsensitiveDict` (full `MutableMapping`, `lower_items`, `copy`,
comparison against plain mappings), `LookupDict`.

## 9. `requests.utils`

`dict_to_sequence, super_len, get_netrc_auth, guess_filename,
extract_zipped_paths, atomic_open, from_key_val_list, to_key_val_list,
parse_list_header, parse_dict_header, unquote_header_value,
dict_from_cookiejar, add_dict_to_cookiejar, get_encodings_from_content,
get_encoding_from_headers, stream_decode_response_unicode, iter_slices,
get_unicode_from_response, unquote_unreserved, requote_uri, address_in_network,
dotted_netmask, is_ipv4_address, is_valid_cidr, set_environ,
should_bypass_proxies, get_environ_proxies, select_proxy, resolve_proxies,
default_user_agent, default_headers, parse_header_links, guess_json_utf,
prepend_scheme_if_needed, get_auth_from_url, check_header_validity,
urldefragauth, rewind_body` and the constants `DEFAULT_CA_BUNDLE_PATH`,
`NETRC_FILES`, `UNRESERVED_SET`, `CaseInsensitiveDict`.

## 10. `requests.exceptions`

`RequestException, InvalidJSONError, JSONDecodeError, HTTPError,
ConnectionError, ProxyError, SSLError, Timeout, ConnectTimeout, ReadTimeout,
URLRequired, TooManyRedirects, MissingSchema, InvalidSchema, InvalidURL,
InvalidHeader, InvalidProxyURL, ChunkedEncodingError, ContentDecodingError,
StreamConsumedError, RetryError, UnrewindableBodyError, RequestsWarning,
FileModeWarning, RequestsDependencyWarning`.

`JSONDecodeError` is aliased to the stdlib `json.JSONDecodeError` exactly like
upstream, and every exception accepts the `response=` / `request=` keyword
arguments used by `raise_for_status()`.

## 11. Remaining modules

`requests.hooks` (`HOOKS`, `default_hooks`, `dispatch_hook`),
`requests.status_codes` (`codes`), `requests.certs` (`where`),
`requests.help` (`info`, `main`), `requests._internal_utils`
(`to_native_string`, `unicode_is_ascii`), `requests._types`,
`requests.compat` (`urlparse, urlunparse, urljoin, urlsplit, quote, unquote,
basestring, str, bytes, JSONDecodeError, chardet, ...`),
`requests.packages` (`urllib3`, `chardet`, `charset_normalizer`,
`cryptography`, `idna`, `ssl_match_hostname` shims).

## 12. TLS-specific surface (this project's superset)

`requests` code keeps working unchanged; on top of it `tls_client` accepts

* **session construction** — every native knob, e.g.
  `Session(client_identifier="chrome_120", tcp_ttl=64, force_http1=True, ...)`;
* **session attributes after construction** — the same names are read/write
  properties, so `session = Session()` followed by
  `session.proxy = ...` / `session.tcp_mss = 1460` / `session.timeout = 5`
  applies to every later request;
* **per-request overrides** — any of those names may be passed to
  `Session.request(...)` and to each verb helper, in addition to the requests
  arguments.

Static code scanning (`python -m tls_client._static_scan`, wired into CI) walks
the package's AST and fails if any of these three surfaces drifts apart.
