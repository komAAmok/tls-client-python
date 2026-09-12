# Upstream synchronization marker

- Upstream remote: `https://github.com/bogdanfinn/tls-client.git`
- Upstream branch: `upstream/master`
- Last synchronized upstream commit: `34718e1b514b446b95bc68dc4f096247e69c7939`
- Previous common base: `b790a311273f26051935641120de169e497e5943`
- Sync date: `2026-09-11`
- Pre-sync recovery branch: `backup/pre-upstream-20260911`

The merge commit containing this file is the boundary between imported
upstream history and this project's local Python/CFFI layer. Keep upstream
history as real merge parents; do not squash it.

## Local overlay points

These are intentional local changes that overlap upstream-owned files and
must be preserved when resolving future upstream conflicts:

- `client.go`, `client_options.go`, `profiles/profiles.go`: TCP/IP fingerprint
  overrides plus the local request/proxy locking and panic-to-error behavior.
- `roundtripper.go`: the QUIC/HTTP-3 transport construction was split out of
  this file into `roundtripper_http3.go` (tag `!tls_lite`) so a lightweight
  `tls_lite` build variant can exclude QUIC entirely. `http3.NextProtoH3`
  references were replaced by the per-variant `nextProtoH3` identifier.
- `roundtripper_http3.go` (new, `!tls_lite`), `roundtripper_http3_stub.go`
  (new, `tls_lite`), `socks5_udp.go` (`!tls_lite` build tag added): the lite
  build variant ships without QUIC/HTTP-3 and the SOCKS5-UDP QUIC dialer.
- `cffi_binding/main.go`: ABI 2 — `GetAbiVersion` / `GetBuildVariant`
  exports, appended RequestOptions fields (disable_session_tickets,
  tls_keylog_path, root_ca_pem+len) and CustomTlsClient field
  (trust_anchors_payload), cache-key format version 3.
- `cffi_src/factory.go`, `cffi_src/types.go`: TCP/IP fingerprint fields and the
  local cookie-jar construction behavior.
- `example/main.go`: retained legacy local example; upstream split examples
  into subdirectories.
- `tests/client_test.go`, `tests/client_test_utils.go`,
  `tests/header_order_test.go`, and related test files: local BrowserLeaks
  endpoint adaptation.
- `.gitignore` and `Readme.md`: union/local project versions, respectively.

## Python binary ABI boundary

**ABI 2 (2026-09-12): the ABI freeze below is lifted.** The bundled shared
libraries are rebuilt from this source and now export `GetAbiVersion()` (2)
and `GetBuildVariant()` ("full" / "lite"). The C structs evolved
append-only: `RequestOptions` gained `disable_session_tickets`,
`tls_keylog_path`, `root_ca_pem`, `root_ca_pem_len`; `CustomTlsClient`
gained `trust_anchors_payload`. Python's CDEF mirrors both. The Python
wrapper refuses ABI-2-only features against legacy (ABI 1) libraries and
selects binaries via `TLS_CLIENT_VARIANT=lite`.

The cache-key format is version 3: `disable_session_tickets`,
`tls_keylog_path`, `root_ca_pem` (sha256) and the custom-profile
`trust_anchors_payload` participate. Parity is pinned by
`python_tests/test_cache_key_parity.py` and
`cffi_binding/cachekey_parity_test.go` (TestCacheKeyParityWithPython) —
update BOTH sides together or these tests will fail.

Historical note (pre-sync, now resolved): the bundled libraries were built
from the pre-sync local CFFI ABI; `chrome_152` / `chrome_152_PSK` and the
`disable_session_tickets` / `trust_anchors_payload` knobs are exposed only
as of the ABI 2 rebuild.

## Verification

Current sync status: static source audit completed; build/test commands below
were intentionally not executed per request, and no new dependencies were
downloaded for verification.

Run from the repository root:

```powershell
$env:GOCACHE="$PWD/.cache/go-build"
$env:GOMODCACHE="$PWD/.cache/go-mod"
$env:GOTMPDIR="$PWD/.cache/go-tmp"
go test . ./profiles ./cffi_src
python -m compileall -q tls_client cffi_binding
python -c "from tls_client._core import CDEF; print('Python CFFI definition OK')"
git diff --check
```

Network-dependent fingerprint tests and the Windows C shared-library build
need their external services/toolchain and are tracked separately from the
offline compatibility checks above.
