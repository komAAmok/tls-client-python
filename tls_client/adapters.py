"""Transport adapter exports."""

from tls_client.requests_compat import BaseAdapter, TLSClientAdapter

HTTPAdapter = TLSClientAdapter

__all__ = ["BaseAdapter", "HTTPAdapter", "TLSClientAdapter"]

