"""Requests-compatible utility helpers.

Mirrors requests.utils.  Only the pure-Python parts are ported: the urllib3
specific helpers (make_headers, parse_url) and the certifi CA bundle are
reimplemented locally so the package keeps its '' cffi dependency set.
"""

import codecs
import contextlib
import os
import re
import socket
import struct
import tempfile
import warnings
import zipfile
from collections import OrderedDict
from io import UnsupportedOperation
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote, unquote, urlparse, urlunparse
from urllib.request import getproxies, proxy_bypass

from tls_client import certs
from tls_client.__version__ import __version__
from tls_client._internal_utils import to_native_string, unicode_is_ascii  # noqa: F401
from tls_client.compat import parse_http_list as _parse_list_header
from tls_client.cookies import cookiejar_from_dict
from tls_client.exceptions import (
    FileModeWarning,
    InvalidHeader,
    InvalidURL,
    UnrewindableBodyError,
)
from tls_client.structures import CaseInsensitiveDict

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NETRC_FILES = (".netrc", "_netrc")
DEFAULT_PORTS = {"http": 80, "https": 443}

#: Windows-only helper; requests exposes a registry-reading variant there.
proxy_bypass_registry = None
DEFAULT_CA_BUNDLE_PATH = certs.where()
DEFAULT_ACCEPT_ENCODING = ", ".join(
    dict.fromkeys(("gzip", "deflate", "br", "zstd", "identity"))
)
integer_types = (int,)
basestring = (str, bytes)

# The unreserved URI characters (RFC 3986)
UNRESERVED_SET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)

_HEADER_VALIDATORS_STR = (
    re.compile(r"^[^:\s][^:\r\n]*\Z"),
    re.compile(r"^\S[^\r\n]*\Z|^\Z"),
)
_HEADER_VALIDATORS_BYTE = (
    re.compile(rb"^[^:\s][^:\r\n]*\Z"),
    re.compile(rb"^\S[^\r\n]*\Z|^\Z"),
)


def _parse_content_type_header(header: str) -> Tuple[str, Dict[str, str]]:
    """Return (content type, params) parsed from a Content-Type header value."""
    tokens = header.split(";")
    content_type, params = tokens[0].strip(), tokens[1:]
    params_dict: Dict[str, str] = {}
    strip_chars = "\"' "
    for param in params:
        param = param.strip()
        if param and "=" in param:
            key, value = param.split("=", 1)
            params_dict[key.strip(strip_chars).lower()] = value.strip(strip_chars)
    return content_type, params_dict


def _validate_header_part(header, header_part, header_validator_index):
    if isinstance(header_part, str):
        validator = _HEADER_VALIDATORS_STR[header_validator_index]
    elif isinstance(header_part, bytes):
        validator = _HEADER_VALIDATORS_BYTE[header_validator_index]
    else:
        raise InvalidHeader(
            f"Header part ({header_part!r}) from {header} "
            f"must be of type str or bytes, not {type(header_part)}"
        )

    if not validator.match(header_part):
        header_kind = "name" if header_validator_index == 0 else "value"
        raise InvalidHeader(
            f"Invalid leading whitespace, reserved character(s), or return "
            f"character(s) in header {header_kind}: {header_part!r}"
        )


def dict_to_sequence(d):
    """Returns an internal sequence dictionary update."""
    if hasattr(d, "items"):
        return d.items()
    return d


def super_len(o) -> int:
    total_length = None
    current_position = 0

    if isinstance(o, str):
        # urllib3 2.x+ treats all strings as utf-8 instead of latin-1.
        o = o.encode("utf-8")

    if hasattr(o, "__len__"):
        total_length = len(o)

    elif hasattr(o, "len"):
        total_length = o.len

    elif hasattr(o, "fileno"):
        try:
            fileno = o.fileno()
        except (UnsupportedOperation, AttributeError):
            pass
        else:
            total_length = os.fstat(fileno).st_size

            # Having used fstat to determine the file length, we need to
            # confirm that this file was opened up in binary mode.
            if "b" not in getattr(o, "mode", ""):
                warnings.warn(
                    (
                        "Requests has determined the content-length for this "
                        "request using the binary size of the file: however, the "
                        "file has been opened in text mode (i.e. without the 'b' "
                        "flag in the mode). This may lead to an incorrect "
                        "content-length."
                    ),
                    FileModeWarning,
                )

    if hasattr(o, "tell"):
        try:
            current_position = o.tell()
        except OSError:
            # This can happen in some weird situations, such as when the file
            # is actually a special file descriptor like stdin.
            if total_length is not None:
                current_position = total_length
        else:
            if hasattr(o, "seek") and total_length is None:
                # StringIO and BytesIO have seek but no usable fileno
                try:
                    # seek to end of file
                    o.seek(0, 2)
                    total_length = o.tell()

                    # seek back to current position to support
                    # partially read file-like objects
                    o.seek(current_position or 0)
                except OSError:
                    total_length = 0

    if total_length is None:
        total_length = 0

    return max(0, total_length - current_position)


def get_netrc_auth(url, raise_errors: bool = False):
    """Returns the Requests tuple auth for a given url from netrc."""
    if isinstance(url, bytes):
        url = url.decode("utf-8")

    netrc_file = os.environ.get("NETRC")
    if netrc_file is not None:
        netrc_locations = (netrc_file,)
    else:
        netrc_locations = tuple("~/%s" % f for f in NETRC_FILES)

    try:
        from netrc import NetrcParseError, netrc

        netrc_path = None

        for f in netrc_locations:
            loc = os.path.expanduser(f)
            if os.path.exists(loc):
                netrc_path = loc
                break

        # Abort early if there isn't one.
        if netrc_path is None:
            return None

        ri = urlparse(url)
        host = ri.hostname

        if host is None:
            return None

        try:
            _netrc = netrc(netrc_path).authenticators(host)
            if _netrc:
                # Return with login / password
                login_i = 0 if _netrc[0] else 1
                return (_netrc[login_i], _netrc[2])
        except (NetrcParseError, OSError):
            # If there was a parsing error or a permissions issue reading the
            # file, we'll just skip netrc auth unless explicitly asked to
            # raise errors.
            if raise_errors:
                raise

    # App Engine hackiness.
    except (ImportError, AttributeError):
        pass

    return None


def guess_filename(obj):
    """Tries to guess the filename of the given object."""
    name = getattr(obj, "name", None)
    if name and isinstance(name, (str, bytes)) and name[0] != "<" and name[-1] != ">":
        return os.path.basename(name)
    return None


def extract_zipped_paths(path: str) -> str:
    """Replace nonexistent paths that look like they refer to a member of a zip
    archive with the location of an extracted copy of the target, or else
    just return the provided path unchanged.
    """
    if os.path.exists(path):
        # this is already a valid path, no need to do anything further
        return path

    # find the first valid part of the provided path and treat that as a zip
    # archive; assume the rest of the path is the name of a member in the archive
    archive, member = os.path.split(path)
    while archive and not os.path.exists(archive):
        archive, prefix = os.path.split(archive)
        if not prefix:
            break
        member = "/".join([prefix, member])

    if not zipfile.is_zipfile(archive):
        return path

    zip_file = zipfile.ZipFile(archive)
    if member not in zip_file.namelist():
        return path

    # we have a valid zip archive and a valid member of that archive
    suffix = os.path.splitext(member.split("/")[-1])[-1]
    fd, extracted_path = tempfile.mkstemp(suffix=suffix)
    try:
        os.write(fd, zip_file.read(member))
    finally:
        os.close(fd)

    return extracted_path


@contextlib.contextmanager
def atomic_open(filename: str):
    """Write a file to the disk in an atomic fashion"""
    tmp_descriptor, tmp_name = tempfile.mkstemp(dir=os.path.dirname(filename))
    try:
        with os.fdopen(tmp_descriptor, "wb") as tmp_handler:
            yield tmp_handler
        os.replace(tmp_name, filename)
    except BaseException:
        os.remove(tmp_name)
        raise


def from_key_val_list(value):
    """Take an object and test to see if it can be represented as a
    dictionary.  Unless it can not be represented as such, return an
    OrderedDict, e.g.::

        >>> from_key_val_list([('key', 'val')])
        OrderedDict([('key', 'val')])
        >>> from_key_val_list('string')
        Traceback (most recent call last):
        ...
        ValueError: cannot encode objects that are not 2-tuples
        >>> from_key_val_list({'key': 'val'})
        OrderedDict([('key', 'val')])
    """
    if value is None:
        return None

    if isinstance(value, (str, bytes, bool, int)):
        raise ValueError("cannot encode objects that are not 2-tuples")

    return OrderedDict(value)


def to_key_val_list(value):
    """Take an object and test to see if it can be represented as a
    dictionary.  If it can be, return a list of tuples, e.g.::

        >>> to_key_val_list([('key', 'val')])
        [('key', 'val')]
        >>> to_key_val_list({'key': 'val'})
        [('key', 'val')]
        >>> to_key_val_list('string')
        Traceback (most recent call last):
        ...
        ValueError: cannot encode objects that are not 2-tuples
    """
    if value is None:
        return None

    if isinstance(value, (str, bytes, bool, int)):
        raise ValueError("cannot encode objects that are not 2-tuples")

    if hasattr(value, "items"):
        return list(value.items())

    return list(value)


def parse_list_header(value: str) -> List[str]:
    """Parse lists as described by RFC 2068 Section 2.

    In particular, parse comma-separated lists where the elements of the list
    may include quoted-strings.  A quoted-string could contain a comma.  A
    non-quoted string could have quotes in the middle.  Quotes are removed
    automatically after parsing.

    >>> parse_list_header('token, "quoted value"')
    ['token', 'quoted value']
    """
    result = []
    for item in _parse_list_header(value):
        if item[:1] == item[-1:] == '"':
            item = unquote_header_value(item[1:-1])
        result.append(item)
    return result


def parse_dict_header(value: str) -> Dict[str, Optional[str]]:
    """Parse lists of key, value pairs as described by RFC 2068 Section 2 and
    convert them into a python dict.

    If there is no value for a key it will be None.
    """
    result: Dict[str, Optional[str]] = {}
    for item in _parse_list_header(value):
        if "=" not in item:
            result[item] = None
            continue
        name, value = item.split("=", 1)
        if value[:1] == value[-1:] == '"':
            value = unquote_header_value(value[1:-1])
        result[name] = value
    return result


def unquote_header_value(value: str, is_filename: bool = False) -> str:
    """Unquotes a header value.  (Reversal of quote_header_value)."""
    if value and value[0] == value[-1] == '"':
        value = value[1:-1]
        # if this is a filename and the starting characters look like a UNC
        # path, then just return the value without quotes.
        if not is_filename or value[:2] != "\\\\":
            return value.replace("\\\\", "\\").replace('\\"', '"')
    return value


def dict_from_cookiejar(cj) -> Dict[str, Any]:
    """Returns a key/value dictionary from a CookieJar."""
    if hasattr(cj, "get_dict"):
        return cj.get_dict()
    return {cookie.name: cookie.value for cookie in cj}


def add_dict_to_cookiejar(cj, cookie_dict):
    """Returns a CookieJar from a key/value dictionary."""
    return cookiejar_from_dict(cookie_dict, cj)


def get_encodings_from_content(content: str) -> List[str]:
    """Returns encodings from given content string."""
    charset_re = re.compile(r'<meta.*?charset=["\']*(.+?)["\'>]', flags=re.I)
    pragma_re = re.compile(r'<meta.*?content=["\']*;?charset=(.+?)["\'>]', flags=re.I)
    xml_re = re.compile(r'^<\?xml.*?encoding=["\']*(.+?)["\'>]')

    return (
        charset_re.findall(content)
        + pragma_re.findall(content)
        + xml_re.findall(content)
    )


def get_encoding_from_headers(headers) -> Optional[str]:
    """Returns encodings from given HTTP Header Dict."""
    content_type = headers.get("content-type")

    if not content_type:
        return None

    content_type, params = _parse_content_type_header(content_type)

    if "charset" in params:
        return params["charset"].strip("'\"")

    if "text" in content_type:
        return "ISO-8859-1"

    if "application/json" in content_type:
        # Assume UTF-8 based on RFC 4627 since the charset was unset.
        return "utf-8"

    return None


def stream_decode_response_unicode(iterator: Iterable[bytes], r):
    """Stream decodes an iterator."""
    if r.encoding is None:
        for item in iterator:
            yield item
        return

    decoder = codecs.getincrementaldecoder(r.encoding)(errors="replace")
    for chunk in iterator:
        rv = decoder.decode(chunk)
        if rv:
            yield rv
    rv = decoder.decode(b"", final=True)
    if rv:
        yield rv


def iter_slices(string, slice_length):
    """Iterate over slices of a string."""
    pos = 0
    if slice_length is None or slice_length <= 0:
        slice_length = len(string)
    while pos < len(string):
        yield string[pos:pos + slice_length]
        pos += slice_length


def get_unicode_from_response(r):
    """Returns the requested content back in unicode.

    Tried:

    1. charset from content-type
    2. fall back and replace all unicode characters
    """
    if r.content is None:
        return None

    tried_encodings: List[str] = []

    # Try charset from content-type
    encoding = get_encoding_from_headers(r.headers)

    if encoding:
        try:
            return str(r.content, encoding)
        except UnicodeError:
            tried_encodings.append(encoding)

    # Fall back:
    try:
        return str(r.content, encoding or "utf-8", errors="replace")
    except TypeError:
        return r.content


def unquote_unreserved(uri: str) -> str:
    """Un-escape any percent-escape sequences in a URI that are unreserved
    characters.  This leaves all reserved, illegal and non-ASCII bytes encoded.
    """
    parts = uri.split("%")
    for i in range(1, len(parts)):
        h = parts[i][0:2]
        if len(h) == 2 and h.isalnum():
            try:
                c = chr(int(h, 16))
            except ValueError:
                raise InvalidURL(f"Invalid percent-escape sequence: '{h}'")

            if c in UNRESERVED_SET:
                parts[i] = c + parts[i][2:]
            else:
                parts[i] = f"%{parts[i]}"
        else:
            parts[i] = f"%{parts[i]}"
    return "".join(parts)


def requote_uri(uri: str) -> str:
    """Re-quote the given URI.

    This function passes the given URI through an unquote/quote cycle to
    ensure that it is fully and consistently quoted.
    """
    safe_with_percent = "!#$%&'()*+,/:;=?@[]~"
    safe_without_percent = "!#$&'()*+,/:;=?@[]~"
    try:
        # Unquote only the unreserved characters, then quote only illegal
        # characters (do not quote reserved, unreserved, or '%')
        return quote(unquote_unreserved(uri), safe=safe_with_percent)
    except InvalidURL:
        # We couldn't unquote the given URI, so let's try quoting it, but
        # there may be unquoted '%'s in the URI.
        return quote(uri, safe=safe_without_percent)


def address_in_network(ip: str, net: str) -> bool:
    """This function allows you to check if an IP belongs to a network subnet

    Example: returns True if ip = 192.168.1.1 and net = 192.168.1.0/24
             returns False if ip = 192.168.1.1 and net = 192.168.100.0/24
    """
    ipaddr = struct.unpack("=L", socket.inet_aton(ip))[0]
    netaddr, bits = net.split("/")
    netmask = struct.unpack("=L", socket.inet_aton(dotted_netmask(int(bits))))[0]
    network = struct.unpack("=L", socket.inet_aton(netaddr))[0] & netmask
    return (ipaddr & netmask) == (network & netmask)


def dotted_netmask(mask: int) -> str:
    """Converts mask from /xx format to xxx.xxx.xxx.xxx

    Example: if mask is 24 function returns 255.255.255.0
    """
    bits = 0xFFFFFFFF ^ (1 << 32 - mask) - 1
    return socket.inet_ntoa(struct.pack(">I", bits))


def is_ipv4_address(string_ip: str) -> bool:
    try:
        socket.inet_aton(string_ip)
    except OSError:
        return False
    return True


def is_valid_cidr(string_network: str) -> bool:
    """Very simple check of the cidr format in no_proxy variable."""
    if string_network.count("/") == 1:
        try:
            mask = int(string_network.split("/")[1])
        except ValueError:
            return False

        if mask < 1 or mask > 32:
            return False

        try:
            socket.inet_aton(string_network.split("/")[0])
        except OSError:
            return False
    else:
        return False
    return True


@contextlib.contextmanager
def set_environ(env_name: str, value: Optional[str]):
    """Set the environment variable 'env_name' to 'value' and restore it after."""
    value_changed = value is not None
    old_value: Optional[str] = None
    if value_changed:
        old_value = os.environ.get(env_name)
        os.environ[env_name] = value
    try:
        yield
    finally:
        if value_changed:
            if old_value is None:
                del os.environ[env_name]
            else:
                os.environ[env_name] = old_value


def should_bypass_proxies(url: str, no_proxy: Optional[str]) -> bool:
    """Returns whether we should bypass proxies or not."""

    # Prioritize lowercase environment variables over uppercase
    # to keep a consistent behaviour with other http projects (curl, wget).
    def get_proxy(key: str) -> Optional[str]:
        return os.environ.get(key) or os.environ.get(key.upper())

    # First check whether no_proxy is defined.  If it is, check that the URL
    # we're getting isn't in the no_proxy list.
    no_proxy_arg = no_proxy
    if no_proxy is None:
        no_proxy = get_proxy("no_proxy")
    parsed = urlparse(url)
    hostname = parsed.hostname

    if hostname is None:
        # URLs don't always have hostnames, e.g. file:/// urls.
        return True

    if no_proxy:
        # We need to see if we match the end of the hostname, both with and
        # without the port.
        no_proxy_hosts = [host for host in no_proxy.replace(" ", "").split(",") if host]

        if is_ipv4_address(hostname):
            for proxy_ip in no_proxy_hosts:
                if is_valid_cidr(proxy_ip):
                    if address_in_network(hostname, proxy_ip):
                        return True
                elif hostname == proxy_ip:
                    # If no_proxy ip was defined in plain IP notation instead of
                    # cidr notation & matches the IP of the index
                    return True
        else:
            host_with_port = hostname
            if parsed.port:
                host_with_port += f":{parsed.port}"

            for host in no_proxy_hosts:
                host = host.lstrip(".")
                if hostname == host or host_with_port == host:
                    return True
                host = "." + host
                if hostname.endswith(host) or host_with_port.endswith(host):
                    return True

    with set_environ("no_proxy", no_proxy_arg):
        try:
            # On POSIX proxy_bypass(host) re-derives the entire proxy
            # environment through proxy_bypass_environment() before it reads
            # no_proxy out of it.  Handing it the mapping getproxies() already
            # produced removes a second full os.environ scan per request.
            # Windows keeps its registry lookup, which this mapping cannot
            # answer.
            if os.name == "nt":
                bypass = proxy_bypass(hostname)
            else:
                bypass = proxy_bypass(hostname, getproxies())
        except (TypeError, socket.gaierror):
            bypass = False

    if bypass:
        return True

    return False


def get_environ_proxies(url: str, no_proxy: Optional[str] = None) -> Dict[str, str]:
    """Return a dict of environment proxies."""
    if should_bypass_proxies(url, no_proxy=no_proxy):
        return {}
    return getproxies()


def select_proxy(url: str, proxies: Optional[Dict[str, str]]) -> Optional[str]:
    """Select a proxy for the url, if applicable.

    :param url: The url being for the request
    :param proxies: A dictionary of schemes or schemes and hosts to proxy URLs
    """
    proxies = proxies or {}
    urlparts = urlparse(url)
    if urlparts.hostname is None:
        return proxies.get(urlparts.scheme, proxies.get("all"))

    proxy_keys = [
        urlparts.scheme + "://" + urlparts.hostname,
        urlparts.scheme,
        "all://" + urlparts.hostname,
        "all",
    ]
    proxy = None
    for proxy_key in proxy_keys:
        if proxy_key in proxies:
            proxy = proxies[proxy_key]
            break

    return proxy


def resolve_proxies(request, proxies, trust_env: bool = True) -> Dict[str, str]:
    """This method takes proxy information from a request and configuration
    input to resolve a mapping of target proxies.  This will consider settings
    such as NO_PROXY to strip proxy configurations.

    :param request: Request or PreparedRequest
    :param proxies: A dictionary of schemes or schemes and hosts to proxy URLs
    :param trust_env: Boolean declaring whether to trust environment configs
    """
    proxies = proxies if proxies is not None else {}
    url = request.url
    scheme = urlparse(url).scheme
    no_proxy = proxies.get("no_proxy")
    new_proxies = proxies.copy()

    if trust_env and not should_bypass_proxies(url, no_proxy=no_proxy):
        environ_proxies = get_environ_proxies(url, no_proxy=no_proxy)

        proxy = environ_proxies.get(scheme, environ_proxies.get("all"))

        if proxy:
            new_proxies.setdefault(scheme, proxy)
    return new_proxies


def default_user_agent(name: str = "python-requests") -> str:
    """Return a string representing the default user agent."""
    return f"{name}/{__version__}"


def default_headers() -> CaseInsensitiveDict:
    return CaseInsensitiveDict(
        {
            "User-Agent": default_user_agent(),
            "Accept-Encoding": DEFAULT_ACCEPT_ENCODING,
            "Accept": "*/*",
            "Connection": "keep-alive",
        }
    )


def parse_header_links(value: str) -> List[Dict[str, str]]:
    """Return a list of parsed link headers proxies.

    i.e. Link: <http:/.../front.jpeg>; rel=front; type="image/jpeg",<http://.../back.jpeg>; rel=back;type="image/jpeg"
    """
    links = []

    replace_chars = " '\""

    value = value.strip(replace_chars)
    if not value:
        return links

    for val in re.split(", *<", value):
        try:
            url, params = val.split(";", 1)
        except ValueError:
            url, params = val, ""

        link = {"url": url.strip("<> '\"")}

        for param in params.split(";"):
            try:
                key, value = param.split("=")
            except ValueError:
                break

            link[key.strip(replace_chars)] = value.strip(replace_chars)

        links.append(link)

    return links


# Null bytes; no need to recreate these on each call to guess_json_utf
_null = "\x00".encode("ascii")
_null2 = _null * 2
_null3 = _null * 3


def guess_json_utf(data: bytes) -> Optional[str]:
    # JSON always starts with two ASCII characters, so detection is as easy as
    # counting the nulls and, from their location and count, determine the
    # encoding.  Also detect a BOM, if present.
    sample = data[:4]
    if sample in (codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE):
        return "utf-32"  # BOM included
    if sample[:3] == codecs.BOM_UTF8:
        return "utf-8-sig"  # BOM included, MS style (discouraged)
    if sample[:2] in (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE):
        return "utf-16"  # BOM included
    nullcount = sample.count(_null)
    if nullcount == 0:
        return "utf-8"
    if nullcount == 2:
        if sample[::2] == _null2:  # 1st and 3rd are null
            return "utf-16-be"
        if sample[1::2] == _null2:  # 2nd and 4th are null
            return "utf-16-le"
        # Did not detect 2 valid UTF-16 ascii-range characters
    if nullcount == 3:
        if sample[:3] == _null3:
            return "utf-32-be"
        if sample[1:] == _null3:
            return "utf-32-le"
        # Did not detect a valid UTF-32 ascii-range character
    return None


def prepend_scheme_if_needed(url: str, new_scheme: str) -> str:
    """Given a URL that may or may not have a scheme, prepend the given scheme.
    Does not replace a present scheme with the one provided as an argument.
    """
    scheme, netloc, path, params, query, fragment = urlparse(url, new_scheme)

    # urlparse is a finicky beast, and sometimes decides that there isn't a
    # netloc present.  Assume it's being naive and take matters into our own
    # hands, as seen in issue #2508.
    if not netloc:
        netloc, path = path, netloc

    return urlunparse((scheme, netloc, path, params, query, fragment))


def get_auth_from_url(url: str) -> Tuple[str, str]:
    """Given a url with authentication components, extract them into a tuple of
    username,password.
    """
    parsed = urlparse(url)

    try:
        auth = (unquote(parsed.username), unquote(parsed.password))
    except (AttributeError, TypeError):
        auth = ("", "")

    return auth


def check_header_validity(header) -> None:
    """Verifies that header parts don't contain leading whitespace
    reserved characters, or return characters.

    :param header: tuple, in the format (name, value).
    """
    name, value = header
    _validate_header_part(header, name, 0)
    _validate_header_part(header, value, 1)


def urldefragauth(url: str) -> str:
    """Given a url remove the fragment and the authentication part."""
    scheme, netloc, path, params, query, _ = urlparse(url)

    # see func:prepend_scheme_if_needed
    if not netloc:
        netloc, path = path, netloc

    netloc = netloc.rsplit("@", 1)[-1]

    return urlunparse((scheme, netloc, path, params, query, ""))


def rewind_body(prepared_request) -> None:
    """Move file pointer back to its recorded starting position
    so it can be read again on redirect.
    """
    body_seek = getattr(prepared_request.body, "seek", None)
    if body_seek is not None and isinstance(
        getattr(prepared_request, "_body_position", None), integer_types
    ):
        try:
            body_seek(prepared_request._body_position)
        except OSError:
            raise UnrewindableBodyError(
                "An error occurred when rewinding request body for redirect."
            )
    else:
        raise UnrewindableBodyError("Unable to rewind request body for redirect.")


