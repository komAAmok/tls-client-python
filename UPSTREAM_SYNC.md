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
  this file into `roundtripper_http3.go`. `http3.NextProtoH3` references were
  replaced by the local `nextProtoH3` identifier.
- `roundtripper_http3.go` (new), `socks5_udp.go` (local QUIC dialer addition):
  QUIC/HTTP-3 and the SOCKS5-UDP QUIC dialer are always built (no lite tier).
- `cffi_binding/main.go`: ABI 2 — `GetAbiVersion` export, appended
  RequestOptions fields (disable_session_tickets, tls_keylog_path,
  root_ca_pem+len) and CustomTlsClient field (trust_anchors_payload),
  cache-key format version 3 (ABI 2.1: version 4 adds h2_max_data_frame_size /
  preface_ping_idle_ms / hpack_indexing_policy; cookie_crumb is per-request
  and not keyed).
  **ABI 3 (2026-09-12):** `GetAbiVersion()` returns 3; RequestOptions gained
  the extension-order policy (`extension_permute_mode` /
  `extension_permute_prefix`), destination-aware header ordering
  (`header_order_by_dest` / `header_order_dest`), `h2_disable_priority_frames`
  and the deep TCP fingerprint (`tcp_dont_fragment`, `tcp_tos`,
  `tcp_no_delay`, `tcp_window_clamp`, `tcp_ip_id_mode`); cache-key format
  version 5.
  (An earlier revision also appended `extension_permute_mode` /
  `extension_permute_prefix` to `CustomTlsClient`; no Go code ever read them —
  the permutation is consumed from `RequestOptions` — so the write-only pair
  was removed again and `CustomTlsClient` is unchanged from ABI 2.)
  **2026-09-13 (pool bound + fork-safety):** a new `//export
  SetPoolMaxEntries(int)` caps the client pool (default 1024, `0` = unlimited,
  `<0` = reset) with LRU eviction so rapid fingerprint rotation cannot grow
  RSS without bound.  The struct layout is unchanged, so `GetAbiVersion()`
  stays 3 (function-only, append-only surface).  Python-side
  `Session.set_pool_max_entries()` raises a clear `RuntimeError` against a
  stale library that predates the export.
- `extension_permute.go` (new), `header_order.go` (new),
  `tcp_fingerprint.go`, `tcp_socket_unix.go`, `tcp_socket_windows.go`,
  `client_options.go`, `client.go`, `roundtripper.go`: the ABI 3 fingerprint
  layer. `extension_permute.go` implements Chromium's per-handshake extension
  shuffle (GREASE/padding/pre_shared_key pinned since Chrome 106);
  `header_order.go` holds the per-`Sec-Fetch-Dest` header-order tables.
  `client_options.go` gained `WithExtensionPermuteMode` and
  `TransportOptions.H2DisablePriorityFrames`; `roundtripper.go` gained
  `newRoundTripperWithPermute` (`newRoundTripper` is retained as a shim for
  `roundtripper_setup_test.go`).
- `profiles/chrome_captured_profiles.go` (generated, 55 majors 99-153),
  `profiles/chrome_captured_registry.go` (new): byte-exact per-version Chrome
  profiles recovered from live captures, registered into `MappedTLSClients`
  for both the plain and the PSK identifier.
- `tools/extract_chrome_captures.py`, `tools/gen_chrome_profiles.py`,
  `tools/_chrome_captures.json` (new): the capture→Go-profile pipeline.
  `gen_chrome_profiles.py --check` is a CI staleness gate.
- `tools/gen_chrome_fingerprint_presets.py`,
  `tls_client/fingerprints/chrome_full.py` (generated, new): the same captures
  rendered as Python presets (base + per-OS variants for all 55 majors).
- `cffi_binding/build_binding.py`: derives the CDEF from `main.go`'s cgo
  preamble *and* the exported prototypes from every `//export` directive in the
  package; there is no hand-maintained CDEF or prototype list to go stale.
- `third_party/fhttp/` (vendored `github.com/bogdanfinn/fhttp` v0.6.9,
  `go.mod` replace): four engine-level realism patches —
  (1) `hpack.Encoder.SetIndexingDecision` + `hpack.IndexingChrome`
  (never index authorization/cookie/set-cookie/content-length/age),
  (2) `Transport.MaxDataFrameSize` DATA-frame payload cap,
  (3) `Transport.PrefacePingIdleMs` Chromium-style PING on idle H2
  connections,
  (4) `Transport.DisablePriorityFrames` (ABI 3) suppresses the RFC 7540
  PRIORITY frames / HEADERS priority flag; plus `Transport.H2*` fields in
  `client_options.go` (TransportOptions) and their wiring in
  `roundtripper.go`.
- `example/main.go`: retained legacy local example; upstream split examples
  into subdirectories.
- `tests/client_test.go`, `tests/client_test_utils.go`,
  `tests/header_order_test.go`, and related test files: local BrowserLeaks
  endpoint adaptation.
- `.gitignore` and `Readme.md`: union/local project versions, respectively.

## Python binary ABI boundary

**ABI 3 (2026-09-12): the deep-fingerprint layer.** The bundled shared
libraries must be rebuilt from this source to expose ABI 3. `GetAbiVersion()`
returns 3 and the C structs evolved append-only again: `RequestOptions` gained
`extension_permute_mode`, `extension_permute_prefix`,
`h2_disable_priority_frames`, `header_order_by_dest`, `header_order_dest`,
`tcp_dont_fragment`, `tcp_tos`, `tcp_no_delay`, `tcp_window_clamp` and
`tcp_ip_id_mode`; `CustomTlsClient` gained `extension_permute_mode` and
`extension_permute_prefix`. Python's CDEF mirrors both — parity is enforced by
`python_tests/test_cdef_parity.py`, which compares the hand-written cdef in
`tls_client/_core.py` against the cdef that `cffi_binding/build_binding.py`
now *derives* from `main.go`, so the two can no longer drift silently.

The tri-state TCP fields (`tcp_dont_fragment`, `tcp_tos`, `tcp_no_delay`) use
`-1` for "leave the profile default alone"; `0` is a meaningful wire value
(DF cleared / TOS 0 / Nagle off). Python's `_normalize_int_fields` preserves
that distinction by mapping a bare `None` to `-1` for exactly those fields.

Unlike the ABI 2 gate (which raises), ABI 3 features **degrade**: a preset or
an implicit default that enables them on a pre-ABI-3 library is reset to its
sentinel with a one-time `RuntimeWarning`, so requests still succeed. Use
`_require_abi3()` directly only when the caller genuinely cannot proceed
without the feature.

The cache-key format is version 5. In addition to the ABI 2 / 2.1 fields, the
extension-order policy (`epm`/`epp`), PRIORITY-frame suppression (`hdpf`) and
the deep TCP fingerprint (`df`/`tos`/`nd`/`wc`/`ipid`) participate.
`header_order_by_dest`, `header_order_dest` and `cookie_crumb` are per-request
wire behaviour and are deliberately **not** keyed. Parity is pinned by
`python_tests/test_cache_key_parity.py` and
`cffi_binding/cachekey_parity_test.go` (TestCacheKeyParityWithPython) —
update BOTH sides together or these tests will fail.

**ABI 2 (2026-09-12).** The bundled shared library exports `GetAbiVersion()`
(returning 3). `RequestOptions` gained `disable_session_tickets`,
`tls_keylog_path`, `root_ca_pem`, `root_ca_pem_len`; `CustomTlsClient` gained
`trust_anchors_payload`. Python's CDEF mirrors both. The Python wrapper
refuses ABI-2-only features against legacy (ABI 1) libraries.

## Build

`cffi_binding/build_binding.py` produces a single full-fidelity build with
`-tags=netgo,osusergo`, `-trimpath -buildvcs=false` and
`-ldflags="-s -w -buildid="` — QUIC/HTTP-3 enabled and the complete profile
catalogue linked. There are no lite/nano tiers: the size-trimmed tiers
(`tls_lite` build tag, `TLS_CLIENT_NANO_PROFILES`, `GetBuildVariant()`) were
removed on 2026-09-13 because the project targets full-dimension browser
fingerprint simulation rather than artifact size. (UPX packing was also
removed earlier: `--shlib` mode silently fails on Go c-shared ELF libraries —
historical Linux artifacts were never actually packed — and packed binaries
trip AV/EDR heuristics while weakening relro/now hardening.)

## Verification

Current sync status: source-level verification completed on 2026-09-12 by
running the offline Go and Python test suites (see below). Per the standing
instruction for this task, the native shared library was **not** rebuilt.

Run from the repository root:

```powershell
$env:GOCACHE="$PWD/.cache/go-build"
$env:GOMODCACHE="$PWD/.cache/go-mod"
$env:GOTMPDIR="$PWD/.cache/go-tmp"
go test . ./profiles
python -m compileall -q tls_client cffi_binding
python -c "from tls_client._core import CDEF; print('Python CFFI definition OK')"
python -m unittest discover -s python_tests -p "test_*.py"
# Generated-table staleness gates (also run in CI):
python tools/gen_chrome_profiles.py --check
python tools/gen_chrome_fingerprint_presets.py --check
git diff --check
```

The Python suite includes four parity guards that exist specifically to catch
cross-language drift, all of which run in CI's `verify-generated` job:

| Test | What it locks down |
| --- | --- |
| `test_cache_key_parity` | Python `_compute_cache_key_hash` ≡ Go `buildCacheKeyFromConfig` (format v5). Pinned vectors are mirrored in `cffi_binding/cachekey_parity_test.go`. |
| `test_cdef_parity` | `_core.py`'s CDEF struct layout ≡ the CDEF derived from `main.go`. |
| `test_export_parity` | Every symbol the CDEF declares is `//export`ed by every build variant's compiled files (and by each generated header, when fresh). |
| `test_session_signature_parity` | `AsyncSession.__init__` accepts exactly the same parameters as `Session.__init__`. |

Network-dependent fingerprint tests and the Windows C shared-library build
need their external services/toolchain and are tracked separately from the
offline compatibility checks above.
