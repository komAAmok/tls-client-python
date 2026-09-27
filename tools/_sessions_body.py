

class Session(TLSOptionsMixin, TLSVerbMixin, SessionRedirectMixin):
    """A Requests session with the complete TLS-client control surface.

    Provides cookie persistence, connection-pooling and configuration - every
    requests.Session attribute and method keeps its meaning - and adds every
    knob the native tls-client engine exposes.

    Basic Usage::

      >>> import tls_client as requests
      >>> s = requests.Session()
      >>> s.get('https://example.com/')
      <Response [200]>

    Session-level TLS knobs can be passed to the constructor, read back, or
    assigned at any time; an assignment applies to every later request::

      >>> s = requests.Session(client_identifier="chrome_120", tcp_ttl=64)
      >>> s.tcp_mss = 1460
      >>> s.get("https://example.com/")

    Every knob is also accepted per request, where it overrides the session
    value for that call only::

      >>> s.get("https://example.com/", tcp_ttl=128)
    """

    __attrs__ = [
        "headers",
        "cookies",
        "auth",
        "proxies",
        "hooks",
        "params",
        "verify",
        "cert",
        "adapters",
        "stream",
        "trust_env",
        "max_redirects",
    ]

    def __init__(
        self,
__INIT_PARAMS__
        **kwargs: Any,
    ) -> None:
        self._setup_requests_attributes(locals())
        self._setup_native_session(locals(), kwargs)
        self._setup_adapters()

    # ------------------------------------------------------------------
    # construction
    # ------------------------------------------------------------------

    def _setup_requests_attributes(self, options: Dict[str, Any]) -> None:
        """Install the attributes requests.Session owns."""
        # Validate the fingerprint identifier before anything else, so an
        # unsupported profile fails fast even when the caller injects a
        # pre-built native session (tests, adapters, connection reuse).
        identifier = options.get("client_identifier")
        if identifier is not None and identifier not in SUPPORTED_CLIENT_IDENTIFIERS:
            raise ValueError("unsupported client_identifier %r" % identifier)

        self.headers = CaseInsensitiveDict(options.get("headers") or {})
        self.params = dict(options.get("params") or {})
        self.auth = options.get("auth")
        self.cookies = RequestsCookieJar()
        merge_cookies(self.cookies, options.get("request_cookies") or {})
        merge_cookies(self.cookies, options.get("cookies") or {})
        self.proxies = _normalize_proxies(options.get("proxies"), options.get("proxy"))
        hooks = options.get("hooks")
        self.hooks = merge_hooks(hooks, None) if hooks else default_hooks()
        self.stream = bool(options.get("stream"))
        self.verify = options.get("verify", True)
        self.cert = options.get("cert")
        self.max_redirects = options.get("max_redirects", DEFAULT_REDIRECT_LIMIT)
        self.trust_env = options.get("trust_env", True)
        self.follow_redirects = bool(options.get("follow_redirects"))
        self._default_timeout = options.get("timeout", 30)
        self._timeout_milliseconds = options.get("timeout_milliseconds", 0)

    def _setup_native_session(
        self, options: Dict[str, Any], extra: Dict[str, Any]
    ) -> None:
        """Create (or adopt) the native engine session behind this facade."""
        native = options.get("_native_session") or extra.pop("_native_session", None)
        if native is None:
            native_options = dict(extra)
            for name, value in options.items():
                if name in REQUESTS_SESSION_EXTRAS or name == "_native_session":
                    continue
                if name in NATIVE_SESSION_OPTION_NAMES:
                    native_options[name] = value
            native_options["without_cookie_jar"] = True
            native = NativeSession(**native_options)
            if extra:
                raise TypeError(
                    "unexpected Session argument: %s" % next(iter(extra))
                )
        self._native = native
        fingerprint = options.get("fingerprint")
        if fingerprint is not None:
            from tls_client.fingerprints import apply as _apply_fingerprint

            _apply_fingerprint(self, fingerprint)

    def _setup_adapters(self) -> None:
        """Attach the default transport adapter for both schemes."""
        adapter = TLSClientAdapter(self._native)
        self.adapters = OrderedDict()
        self.mount("https://", adapter)
        self.mount("http://", adapter)

    # ------------------------------------------------------------------
    # TLS option plumbing (the TLSOptionsMixin properties call these)
    # ------------------------------------------------------------------

    def _get_tls_option(self, name: str) -> Any:
        """Read a session-level TLS knob from the native engine."""
        return getattr(self._native, name)

    def _set_tls_option(self, name: str, value: Any) -> None:
        """Write a session-level TLS knob; applies to every later request."""
        if name in REQUESTS_OWNED_ATTRIBUTES:
            object.__setattr__(self, name, value)
            return
        try:
            setattr(self._native, name, value)
        except AttributeError:
            # Options the engine only accepts at construction time have no
            # native property; record them on the session defaults instead so
            # the next request still observes the value.
            self._native._set_default(name, value)
        if name == "timeout":
            object.__setattr__(self, "_default_timeout", value)

    # ------------------------------------------------------------------
    # requests.Session API
    # ------------------------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        native = self.__dict__.get("_native")
        if native is not None and hasattr(native, name):
            return getattr(native, name)
        raise AttributeError(
            "%r object has no attribute %r" % (type(self).__name__, name)
        )

    def __setattr__(self, name: str, value: Any) -> None:
        native = self.__dict__.get("_native")
        descriptor = getattr(type(native), name, None) if native is not None else None
        if (
            native is not None
            and name not in REQUESTS_OWNED_ATTRIBUTES
            and isinstance(descriptor, property)
        ):
            setattr(native, name, value)
            if name == "timeout":
                object.__setattr__(self, "_default_timeout", value)
            return
        object.__setattr__(self, name, value)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def prepare_request(self, request: Request) -> PreparedRequest:
        """Construct a PreparedRequest for transmission.

        The PreparedRequest has settings merged from the Request instance and
        those of the Session.
        """
        cookies = request.cookies or {}

        # Dict-like and cookie-jar inputs are both accepted.
        if not isinstance(cookies, RequestsCookieJar):
            cookies = cookiejar_from_dict(cookies)

        # Merge with session cookies
        merged_cookies = merge_cookies(
            merge_cookies(RequestsCookieJar(), self.cookies), cookies
        )

        auth = request.auth
        if self.trust_env and not auth and not self.auth:
            auth = get_netrc_auth(request.url)

        p = PreparedRequest()
        p.prepare(
            method=request.method.upper(),
            url=request.url,
            files=request.files,
            data=request.data,
            json=request.json,
            headers=merge_setting(
                request.headers, self.headers, dict_class=CaseInsensitiveDict
            ),
            params=merge_setting(request.params, self.params),
            auth=merge_setting(auth, self.auth),
            cookies=merged_cookies,
            hooks=merge_hooks(request.hooks, self.hooks),
        )
        return p

    def _dispatch_request(
        self,
        method,
        url,
        params=None,
        data=None,
        headers=None,
        cookies=None,
        files=None,
        auth=None,
        timeout=None,
        allow_redirects=None,
        proxies=None,
        hooks=None,
        stream=None,
        verify=None,
        cert=None,
        json=None,
        context=None,
        tls_options=None,
        extra_kwargs=None,
    ):
        """Shared body of request() and the seven verb helpers."""
        tls_options = tls_options or {}
        extra_kwargs = extra_kwargs or {}

        if "follow_redirects" in extra_kwargs:
            allow_redirects = extra_kwargs.pop("follow_redirects")
        body = extra_kwargs.pop("body", None)
        if body is not None and data is None:
            data = body
        proxy = extra_kwargs.pop("proxy", None)
        if proxy is not None:
            # proxy accepts a URL string (both schemes) or a requests-style
            # mapping; fold it into the proxies mapping the adapter consumes.
            base = dict(proxies) if isinstance(proxies, dict) else {}
            proxies = _normalize_proxies(base, proxy)
        if extra_kwargs:
            raise TypeError(
                "unexpected request argument: %s" % next(iter(extra_kwargs))
            )

        if isinstance(url, bytes):
            url = url.decode("utf-8")

        req = Request(
            method=method.upper(),
            url=url,
            headers=headers,
            files=files,
            data=data or {},
            json=json,
            params=params or {},
            auth=auth,
            cookies=cookies,
            hooks=hooks,
        )
        prep = self.prepare_request(req)

        settings = self.merge_environment_settings(
            prep.url, proxies or {}, stream, verify, cert
        )
        settings["timeout"] = self._default_timeout if timeout is None else timeout
        # requests defaults allow_redirects to True; the head() helper passes
        # False explicitly, and follow_redirects=... overrides both.
        settings["allow_redirects"] = True if allow_redirects is None else allow_redirects
        if context is not None:
            settings["context"] = context

        # Per-request TLS overrides travel through the adapter onto the engine.
        for name, value in tls_options.items():
            settings.setdefault("tls_options", {})[name] = value

        return self.send(prep, **settings)

    def execute_request(self, method, url, **kwargs):
        """Send a request through the requests pipeline.

        The native engine exposes an execute_request with the same name; this
        override keeps the requests-compatible arguments (params, json, hooks,
        allow_redirects, ...) working on the facade.
        """
        return self.request(method, url, **kwargs)

    def typed_request(self, request, **kwargs):
        """Send a Request, a PreparedRequest or a mapping describing one."""
        if isinstance(request, PreparedRequest):
            return self.send(request, **kwargs)
        if isinstance(request, Request):
            return self.send(self.prepare_request(request), **kwargs)
        values = dict(request)
        method = values.pop("method")
        url = values.pop("url")
        values.update(kwargs)
        values["method"] = method
        values["url"] = url
        return self._dispatch_request(**values)

    def merge_environment_settings(self, url, proxies, stream, verify, cert):
        """Check the environment and merge it with the given settings."""
        # Gather clues from the surrounding environment.
        if self.trust_env:
            # Set the environment's proxies.
            no_proxy = proxies.get("no_proxy") if proxies is not None else None
            env_proxies = get_environ_proxies(url, no_proxy=no_proxy)
            for (k, v) in env_proxies.items():
                proxies.setdefault(k, v)

            # Look for requests environment configuration and be compatible
            # with the cURL behaviour of ignoring certs from the environment.
            if verify is True or verify is None:
                verify = (
                    os.environ.get("REQUESTS_CA_BUNDLE")
                    or os.environ.get("CURL_CA_BUNDLE")
                    or verify
                )

        # Merge all the kwargs.
        proxies = merge_setting(proxies, self.proxies)
        stream = merge_setting(stream, self.stream)
        verify = merge_setting(verify, self.verify)
        cert = merge_setting(cert, self.cert)

        return {"proxies": proxies, "stream": stream, "verify": verify, "cert": cert}

    def get_adapter(self, url):
        """Returns the appropriate connection adapter for the given URL."""
        for (prefix, adapter) in self.adapters.items():
            if url.lower().startswith(prefix.lower()):
                return adapter

        raise exceptions.InvalidSchema("No connection adapters were found for %r" % url)

    def mount(self, prefix, adapter):
        """Registers a connection adapter to a prefix.

        Adapters are sorted in descending order by prefix length.
        """
        self.adapters[prefix] = adapter
        keys_to_move = [k for k in self.adapters if len(k) < len(prefix)]

        for key in keys_to_move:
            self.adapters[key] = self.adapters.pop(key)

    def close(self):
        """Closes all adapters and, as such, the Session."""
        for adapter in set(self.adapters.values()):
            adapter.close()

    def __getstate__(self):
        """Pickle the requests-visible state.

        The transport adapter owns the native engine session, which holds a
        lock and a live Go client pool and therefore cannot be serialised.
        Adapters are rebuilt on unpickling, exactly as a fresh Session would
        build them, so the session's cookies, headers and configuration - the
        part requests promises to preserve - survive the round trip.
        """
        state = {attr: getattr(self, attr, None) for attr in self.__attrs__}
        # Rebuilt by __setstate__ from the engine defaults.
        state.pop("adapters", None)
        return state

    def __setstate__(self, state):
        for attr, value in state.items():
            setattr(self, attr, value)

        # The cookie jar is rebuilt from the pickled pairs so the policy
        # objects are fresh for this process.
        self.cookies = cookiejar_from_dict(dict(self.cookies.items()))

        # Attributes that are not part of __attrs__ still need defaults.
        if self.__dict__.get("_default_timeout") is None:
            self._default_timeout = 30
        if self.__dict__.get("_timeout_milliseconds") is None:
            self._timeout_milliseconds = 0

        # Rebuild the engine session and the adapters that __getstate__ dropped.
        # Only the requests-visible transport defaults are restored; the TLS
        # knobs live on the engine and are not part of the pickled state.
        self._native = NativeSession(verify=self.verify, without_cookie_jar=True)
        self._setup_adapters()


def session():
    """Returns a Session for context-manager usage."""
    return Session()
