"""Browser-coherent request contexts (Sec-Fetch-*, Client Hints, Priority).

Real browsers derive a family of request headers from *how* the request was
initiated (a top-level navigation, an XHR, an <img> load, ...).  Sending a
top-level-navigation ``Accept`` with an XHR ``Sec-Fetch-Mode`` — or omitting
the ``Sec-Fetch-*`` cluster entirely — is a strong automation tell.

This module lets callers describe the *context* of a request and derives the
coherent header set for it.  Everything is opt-in: pass ``context=...`` to
``Session.request`` / ``execute_request`` and the derived headers are merged
under the user's explicit headers (user values win).

Techniques mirror the behaviour captured in real Chrome / Firefox traffic
(same model as httpcloak's RequestContext and priority-urgency table):

- ``Sec-Fetch-Mode/Dest/Site`` per request context, ``Sec-Fetch-User: ?1``
  only for user-triggered navigations;
- fetch-site computation from target URL vs referrer (registrable-domain
  matching, simplified two-label heuristic);
- ``Priority: u=,i`` from the resource urgency table (Chrome semantics:
  urgency 3 omits the ``u=`` component);
- ``Accept`` per destination and browser;
- ``Upgrade-Insecure-Requests: 1`` only on navigations.
"""

from typing import Dict, Optional
from urllib.parse import urlsplit


class RequestContext:
    """Describes how a request was initiated inside a browser page.

    Attributes mirror the observable ``Sec-Fetch-*`` / ``Priority`` /
    ``Accept`` header family.
    """

    __slots__ = (
        "mode",
        "dest",
        "site",
        "user_triggered",
        "referrer",
        "target_url",
        "urgency",
        "incremental",
    )

    def __init__(
        self,
        mode: str = "navigate",
        dest: str = "document",
        site: Optional[str] = None,
        user_triggered: bool = False,
        referrer: Optional[str] = None,
        target_url: Optional[str] = None,
        urgency: Optional[int] = None,
        incremental: bool = False,
    ) -> None:
        self.mode = mode
        self.dest = dest
        self.site = site
        self.user_triggered = user_triggered
        self.referrer = referrer
        self.target_url = target_url
        self.urgency = urgency
        self.incremental = incremental

    # -- context constructors (mirror common page initiations) -------------

    @classmethod
    def navigation(cls, url: str, *, user_triggered: bool = True,
                   referrer: Optional[str] = None) -> "RequestContext":
        """Top-level document navigation (address bar, link click)."""
        return cls(mode="navigate", dest="document", user_triggered=user_triggered,
                   referrer=referrer, target_url=url)

    @classmethod
    def iframe(cls, url: str, *, referrer: Optional[str] = None) -> "RequestContext":
        return cls(mode="navigate", dest="iframe", referrer=referrer, target_url=url)

    @classmethod
    def xhr(cls, url: str, *, referrer: Optional[str] = None) -> "RequestContext":
        """fetch()/XHR — the default sub-resource data request."""
        return cls(mode="cors", dest="empty", referrer=referrer, target_url=url)

    @classmethod
    def script(cls, url: str, *, referrer: Optional[str] = None) -> "RequestContext":
        return cls(mode="no-cors", dest="script", referrer=referrer, target_url=url)

    @classmethod
    def style(cls, url: str, *, referrer: Optional[str] = None) -> "RequestContext":
        return cls(mode="no-cors", dest="style", referrer=referrer, target_url=url)

    @classmethod
    def image(cls, url: str, *, referrer: Optional[str] = None) -> "RequestContext":
        return cls(mode="no-cors", dest="image", referrer=referrer, target_url=url)

    @classmethod
    def font(cls, url: str, *, referrer: Optional[str] = None) -> "RequestContext":
        return cls(mode="cors", dest="font", referrer=referrer, target_url=url)

    @classmethod
    def media(cls, url: str, *, referrer: Optional[str] = None) -> "RequestContext":
        return cls(mode="no-cors", dest="video", referrer=referrer, target_url=url)


# ---------------------------------------------------------------------------
# Chrome's resource priority table (urgency, incremental) per destination —
# captured from real Chrome 147 traffic (same data as httpcloak's
# defaultPriorityTable).  Urgency 3 is Chrome's internal default and is
# OMITTED from the header; 0-7 map to H2 stream weight 256-(73*u)/2.
# ---------------------------------------------------------------------------

_DEFAULT_URGENCY: Dict[str, int] = {
    "audio": 3,
    "document": 0,
    "embed": 0,
    "empty": 1,
    "font": 1,
    "iframe": 0,
    "image": 2,
    "manifest": 2,
    "object": 0,
    "script": 1,
    "style": 0,
    "track": 3,
    "video": 3,
    "worker": 4,
}

_DEFAULT_INCREMENTAL = frozenset((
    "audio", "document", "embed", "empty", "iframe", "image",
    "object", "track", "video", "worker",
))

_CHROME_PRIORITY_DEFAULT_URGENCY = 3


def _registrable_domain(host: str) -> str:
    """Simplified registrable-domain heuristic (two-label suffix).

    Matches httpcloak's calculateFetchSite: good enough for the
    same-site/cross-site distinction without a full PSL dependency.
    """
    labels = host.lower().split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    return ".".join(labels[-2:])


def compute_fetch_site(target_url: str, referrer: Optional[str]) -> str:
    """Compute ``Sec-Fetch-Site`` for a request given its referrer.

    ``none`` when there is no referrer (address-bar navigation),
    ``same-origin`` / ``same-site`` / ``cross-site`` otherwise.
    """
    if not referrer:
        return "none"
    t_host = (urlsplit(target_url).hostname or "").lower()
    r_host = (urlsplit(referrer).hostname or "").lower()
    if not t_host or not r_host:
        return "none"
    if t_host == r_host:
        return "same-origin"
    if _registrable_domain(t_host) == _registrable_domain(r_host):
        return "same-site"
    return "cross-site"


def sec_fetch_headers(ctx: RequestContext) -> Dict[str, str]:
    """Derive the ``Sec-Fetch-*`` cluster for *ctx*."""
    headers = {
        "sec-fetch-mode": ctx.mode,
        "sec-fetch-dest": ctx.dest,
    }
    site = ctx.site
    if site is None:
        site = compute_fetch_site(ctx.target_url or "", ctx.referrer)
    headers["sec-fetch-site"] = site
    if ctx.mode == "navigate" and ctx.user_triggered:
        headers["sec-fetch-user"] = "?1"
    return headers


def priority_header(ctx: RequestContext) -> Optional[str]:
    """Build the RFC 9218 ``Priority`` header value (Chrome emission rules).

    Urgency defaults to the per-destination captured table; incremental
    likewise.  Urgency 3 is Chrome's internal default: it is omitted from
    the header, so urgency-3 non-incremental requests carry no Priority
    header at all, and urgency-3 incremental requests send just ``i``.
    """
    urgency = ctx.urgency
    if urgency is None:
        urgency = _DEFAULT_URGENCY.get(ctx.dest, _CHROME_PRIORITY_DEFAULT_URGENCY)
    incremental = ctx.incremental
    if not ctx.incremental and ctx.urgency is None:
        incremental = ctx.dest in _DEFAULT_INCREMENTAL
    is_default = urgency == _CHROME_PRIORITY_DEFAULT_URGENCY
    if is_default and not incremental:
        return None
    if is_default and incremental:
        return "i"
    if incremental:
        return "u=%d, i" % urgency
    return "u=%d" % urgency


# ---------------------------------------------------------------------------
# Accept values per destination (Chrome / Firefox behaviour)
# ---------------------------------------------------------------------------

_CHROME_NAVIGATION_ACCEPT = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,"
    "image/avif,image/webp,image/apng,*/*;q=0.8,"
    "application/signed-exchange;v=b3;q=0.7"
)
_FIREFOX_NAVIGATION_ACCEPT = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,"
    "image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8"
)
# Safari sends the same navigation Accept as Chrome but without the
# signed-exchange token, which is a Chromium-only feature.
_SAFARI_NAVIGATION_ACCEPT = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
)
_CHROME_EMPTY_ACCEPT = "*/*"
_FIREFOX_EMPTY_ACCEPT = "*/*"
_IMAGE_ACCEPT = (
    "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"
)
_STYLE_ACCEPT = "text/css,*/*;q=0.1"
_SCRIPT_ACCEPT = (
    "application/javascript, application/*-javascript+module, text/javascript, */*;q=0.5"
)


def _accept_for(ctx: RequestContext, browser: str) -> str:
    """Navigation/XHR Accept header for *browser* ("" = unknown family).

    An unknown family falls back to the Chromium value, which matches the
    pre-existing behaviour for identifiers the engine does not recognise.
    """
    if ctx.dest == "document":
        if browser == "firefox":
            return _FIREFOX_NAVIGATION_ACCEPT
        if browser == "safari":
            return _SAFARI_NAVIGATION_ACCEPT
        return _CHROME_NAVIGATION_ACCEPT
    if ctx.dest == "image":
        return _IMAGE_ACCEPT
    if ctx.dest == "style":
        return _STYLE_ACCEPT
    if ctx.dest == "script":
        return _SCRIPT_ACCEPT
    return _FIREFOX_EMPTY_ACCEPT if browser == "firefox" else _CHROME_EMPTY_ACCEPT


def apply_context(
    headers: Optional[Dict[str, str]],
    ctx: RequestContext,
    *,
    browser: str = "chrome",
    send_priority: bool = True,
    user_keys: Optional[set] = None,
) -> Dict[str, str]:
    """Merge the context-derived headers into *headers*.

    *user_keys* (casefolded header names) are the headers the caller set
    explicitly on this request — they always win.  Everything else that
    the context owns is overridden or removed, because values inherited
    from the profile's default header block (a navigation Accept, a
    document ``Sec-Fetch-Mode``) would contradict this request's context.
    """
    merged = dict(headers) if headers else {}
    user = user_keys or set()

    def _folded_key(name: str) -> Optional[str]:
        for key in merged:
            if key.casefold() == name:
                return key
        return None

    def _override(name: str, value: Optional[str]) -> None:
        if value is None:
            return
        existing = _folded_key(name)
        if existing is not None:
            if existing.casefold() not in user:
                merged[existing] = value
            return
        merged[name] = value

    def _remove(name: str) -> None:
        existing = _folded_key(name)
        if existing is not None and existing.casefold() not in user:
            del merged[existing]

    for name, value in sec_fetch_headers(ctx).items():
        _override(name, value)
    if ctx.mode != "navigate" or not ctx.user_triggered:
        _remove("sec-fetch-user")
    _override("accept", _accept_for(ctx, browser))
    if ctx.mode == "navigate":
        _override("upgrade-insecure-requests", "1")
    else:
        _remove("upgrade-insecure-requests")
    if send_priority:
        _override("priority", priority_header(ctx))
    return merged


def expand_client_hints(
    sec_ch_ua: str,
    *,
    platform: str = '"Windows"',
    platform_version: str = '"10.0.0"',
    architecture: str = '"x86"',
    bitness: str = '"64"',
    model: str = '""',
    mobile: str = "?0",
    ua_full_version: Optional[str] = None,
) -> Dict[str, str]:
    """Expand the low-entropy client-hint trio into the full set.

    Every brand's version is expanded to ``major.0.0.0`` (Chromium
    semantics, keeping the GREASE brand token verbatim).  When
    *ua_full_version* is given, the real browser brands (Chromium, Google
    Chrome, Microsoft Edge, Brave) get that exact full version while the
    GREASE brand keeps its own padded version — matching how Chrome
    reports ``sec-ch-ua-full-version-list``.
    """
    import re

    full_list = re.sub(r';v="(\d+)"', lambda m: ';v="%s.0.0.0"' % m.group(1), sec_ch_ua)
    if ua_full_version:
        full_list = re.sub(
            r'"((?:Chromium|Google Chrome|Microsoft Edge|Brave))";v="\d+\.0\.0\.0"',
            lambda m: '"%s";v="%s"' % (m.group(1), ua_full_version),
            full_list,
        )
    return {
        "sec-ch-ua": sec_ch_ua,
        "sec-ch-ua-mobile": mobile,
        "sec-ch-ua-platform": platform,
        "sec-ch-ua-full-version-list": full_list,
        "sec-ch-ua-platform-version": platform_version,
        "sec-ch-ua-arch": architecture,
        "sec-ch-ua-bitness": bitness,
        "sec-ch-ua-model": model,
    }
