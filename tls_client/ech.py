"""ECH (Encrypted Client Hello) config resolution.

Resolves a hostname's ECHConfigList from DNS HTTPS records (RFC 9460) via
the binding's DoH-based resolver and converts it into the
``ech_candidate_payloads`` form that ``custom_tls_client`` expects.

    from tls_client import ech

    payload = ech.resolve("tls.peet.ws")
    session = Session(custom_tls_client={
        "ja3_string": "...",
        "ech_candidate_payloads": ech.to_candidate_payloads(payload),
    })

Resolving on the Go side keeps the Python side free of DNS dependencies;
results are cached per host (1 h TTL, negative results 5 min).  Re-resolve
after an ``illegal_parameter`` handshake failure — Cloudflare rotates ECH
keys periodically and the cached config may be stale.  Not available in
the lite build (returns None).
"""

from typing import List, Optional

import tls_client._core as _core


def resolve(host: str) -> Optional[bytes]:
    """Return the raw ECHConfigList bytes advertised for *host*, or None.

    Requires the ABI-2 native library (rebuild from current source).
    """
    _core._get_ffi()
    _core._require_abi2()
    raw = _core._lib.ResolveECHConfig(host.encode("utf-8"))
    if not raw or raw == _core._ffi.NULL:
        return None
    return bytes.fromhex(_core._ffi.string(raw).decode("ascii"))


def to_candidate_payloads(ech_config_list: bytes) -> List[int]:
    """Convert raw ECHConfigList bytes into ``ech_candidate_payloads``.

    The Go engine consumes the ECHConfigList as big-endian 16-bit words.
    """
    if len(ech_config_list) % 2:
        ech_config_list = ech_config_list + b"\x00"
    return [
        int.from_bytes(ech_config_list[i:i + 2], "big")
        for i in range(0, len(ech_config_list), 2)
    ]
