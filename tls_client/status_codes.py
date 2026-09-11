"""HTTP status-code lookup compatible with ``requests.codes``."""

from tls_client.structures import LookupDict


codes = LookupDict(name="status_codes")

_NAMES = {
    100: ("continue",),
    200: ("ok", "okay", "all_ok"),
    201: ("created",),
    202: ("accepted",),
    204: ("no_content",),
    206: ("partial_content",),
    300: ("multiple_choices",),
    301: ("moved_permanently", "moved"),
    302: ("found",),
    303: ("see_other",),
    304: ("not_modified",),
    307: ("temporary_redirect", "temporary_moved"),
    308: ("permanent_redirect",),
    400: ("bad_request", "bad"),
    401: ("unauthorized",),
    403: ("forbidden",),
    404: ("not_found", "not_found"),
    405: ("method_not_allowed",),
    408: ("request_timeout", "timeout"),
    409: ("conflict",),
    410: ("gone",),
    413: ("request_entity_too_large",),
    415: ("unsupported_media_type",),
    418: ("im_a_teapot", "teapot"),
    422: ("unprocessable_entity",),
    429: ("too_many_requests", "too_many"),
    500: ("internal_server_error", "server_error"),
    502: ("bad_gateway",),
    503: ("service_unavailable", "unavailable"),
    504: ("gateway_timeout",),
}

for _code, _names in _NAMES.items():
    setattr(codes, "_%s" % _code, _code)
    for _name in _names:
        setattr(codes, _name, _code)

