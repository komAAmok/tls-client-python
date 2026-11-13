# Upstream synchronization marker

- Upstream remote: `https://github.com/bogdanfinn/tls-client.git`
- Upstream tag: `v1.18.1` (`9525980ec9f9f83d402aff06436a1e3db17e730a`)
- Previous sync point: upstream `v1.16.0` (`23b44420627619a30d09be5b6250e6cf2e350cf2`)
- Sync date: `2026-11-12`
- Pre-sync recovery tag: `backup/pre-upstream-20261112`

The merge commit containing this file is the boundary between imported
upstream history and this project's local Python/CFFI layer. Keep upstream
history as real merge parents; do not squash it.

## Local overlay points

These are intentional local changes that overlap upstream-owned files and
must be preserved when resolving future upstream conflicts:

- `client.go`, `client_options.go`, `profiles/profiles.go`: TCP/IP fingerprint
  overrides plus the local request/proxy locking and panic-to-error behavior.
  **2026-10-02 (binary size):** the debug body-preview in `client.go` now calls
  the local `newCharsetReader` (`charset_lean.go`) instead of
  `golang.org/x/net/html/charset.NewReader`, and the `html/charset` import was
  dropped. `html/charset` links the entire `x/text/encoding` registry through
  `htmlindex`, including both directions of the CJK conversion tables, for a
  transcode that only ever runs when `with_debug` is set. The replacement
  removes ~110 KB from the linux/amd64 shared library (14,095,224 →
  13,984,760 bytes, −0.8%).
  The `charset_lean.go` switch must keep calling `X.NewDecoder()` directly:
  storing those methods as values (a map of method values, an
  `encoding.Encoding` table) keeps the interface itabs — and with them the
  encode tables — linked, which gives back most of the saving.

  **The debug preview no longer rewrites the response.** Upstream hands the
  charset-decoded bytes back as `resp.Body`; that made `with_debug` change the
  payload the caller received, not just the log line. A binary body went
  through the windows-1252 fallback (which rewrites every byte in 0x80-0x9F),
  so an image came back longer than the server sent it, and a text body became
  UTF-8 while `Content-Type` still named the original charset, so a client
  decoding by the header (`Response.text`) decoded it twice and produced
  mojibake. `client.go` now keeps the original bytes on `resp.Body` and sends
  only the log line through `decodeBodyForLog`; `isTextualContentType` keeps
  binary payloads out of the decoder so the log does not fill with replacement
  characters. Pinned by `python_tests/test_requests_behaviour.py`
  (`test_debug_session_returns_the_exact_response_bytes`,
  `test_debug_session_decodes_text_exactly_once`,
  `test_debug_and_plain_sessions_agree_on_the_body`).

  The replacement is a **behavioural** drop-in, not a subset: it reproduces
  `html/charset.DetermineEncoding` in full — the WHATWG label table generated
  from `x/text/encoding/htmlindex`, the BOM sniff, the `<meta>` prescan (via
  `x/net/html`'s tokenizer, ~24 KB), the UTF-8 validity probe and the
  windows-1252 fallback — including the distinction between `encoding.Nop`
  (detected UTF-8, body passed through) and a real UTF-8 decoder (explicit
  label, invalid bytes become U+FFFD). `TestCharsetLeanMatchesUpstream` in
  `charset_lean_test.go` imports the real `html/charset` and diffs the two
  across every label and detection path; keep it passing when touching either
  file. Note the earlier decode-only subset silently diverged on
  `iso-8859-1`/`latin1`/`us-ascii`/`ascii`/`cp819`/`iso-ir-100` (htmlindex maps
  those to windows-1252, not ISO-8859-1) and on `<meta>`-declared charsets.
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
  **Concurrency overlay (2026-10-02):** `tls_client/_core.py`'s async request
  path resolved its per-request `client_identifier` override against the *live*
  session default instead of the snapshot the request was built from. A
  concurrent `session.client_identifier = ...` landing in that window made the
  two compare equal, skipping the header re-pairing and sending the snapshot
  profile's User-Agent with the override's TLS fingerprint. Both paths now read
  the snapshot. Pinned by
  `test_async_override_pairs_headers_with_the_resolved_identifier`.

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
- `tls_client/_core.py` + `tools/_sessions_body.py`: the identifier allowlist
  is no longer `frozenset(DEFAULT_HEADERS)`. That derivation rejected the 35
  captured Chrome majors that have no hand-written header block
  (`chrome_100`, `chrome_113`, `chrome_121`, …), which also made their
  fingerprint presets unusable. The allowlist now unions the header table with
  `fingerprints.chrome_full.CAPTURED_CHROME_MAJORS`, which
  `tools/gen_chrome_fingerprint_presets.py` emits from
  `tools/_chrome_captures.json` — so a new capture widens the allowlist with no
  Python edit. `python_tests/test_supported_identifiers.py` pins both
  directions: every capture is accepted, and nothing is accepted that the
  engine has not registered (a too-wide allowlist would turn a clean
  `ValueError` into an engine error at request time).
- `tls_client/websocket.py` + `cffi_binding/main.go`: `WebsocketOptions`
  gained `enable_compression` (ABI 4, append-only) so upstream's
  `WithEnableCompression` is reachable from Python as `WebSocket(..., compression=True)`.
  Without it every client looked like one that does not offer
  `permessage-deflate`, which is itself a handshake-level difference.
  Pinned by `python_tests/test_websocket_compression.py`, which reads the
  upgrade request off a local socket.
- `tools/_sessions_body.py`: the requests-compatible `Session` forwards
  `stream_to_file` to the native session. It previously existed only on
  `NativeSession`, so the documented call raised `AttributeError` from the
  class the docs point at. `python_tests/test_facade_surface_parity.py` now
  walks both classes per instance, so the next native method that is not
  re-exposed fails a test instead of shipping.

## Upstream v1.16.0 → v1.18.1 delta and how it was reconciled

The upstream import was performed as a file-level three-way merge with
`/tmp/up116` (v1.16.0, our previous sync base) as the common ancestor and
`/tmp/up181` (v1.18.1) as the incoming side, so every upstream-owned file
either took upstream verbatim (when our copy was untouched since v1.16.0) or
was reconciled hunk by hunk against the documented overlay points above.
Upstream history stays a real parent where it exists; nothing was squashed.

### Upstream changes carried in

| Area | Change |
| --- | --- |
| `go.mod` | `go 1.27`; fhttp 0.6.9 → **0.7.3**, utls 1.7.8 → **1.8.2-barnius**, quic-go-utls 1.0.10 → 1.0.13, websocket 1.5.6 → 1.5.9, x/net 0.48 → 0.59, x/text 0.32 → 0.42, klauspost/compress 1.18.2 → 1.20.1, brotli 1.2.0 → 1.2.7, + `molecule-man/go-brrr` |
| `trust_anchors/` (new package) | the Chrome Root Store anchor list plus `Split`/`Encode`/`Sort`/`Shuffle`/`BuildPayload`. Chrome 154+ **sorts** the 0xCA34 IDs (stable per process) while ≤153 shuffles per process. `profiles.BuildTrustAnchorsPayload` is now a deprecated shim over `trust_anchors.BuildPayload`. |
| `profiles/extension_data.go`, `profiles/grease.go` | **deleted upstream**; the capture and the GREASE-signature helper moved into `trust_anchors/` and into `tls.GREASE_PLACEHOLDER` (utls resolves it in `ApplyPreset`). Nothing local referenced either symbol. |
| `profiles/internal_browser_profiles.go` | Chrome 154 / 154_PSK added (byte-identical ClientHello to 152, sorted anchors); `profiles/contributed_browser_profiles.go` gains Safari 27.2. Both registered in `MappedTLSClients`. |
| `client.go` / `client_options.go` | `HttpClient.Close()` (releases HTTP/3 UDP sockets — `CloseIdleConnections` does not); `WithCertificatePinner` (custom `CertificatePinner`, takes precedence over `WithCertificatePinning`); `TransportOptions.ReadIdleTimeout` / `PingTimeout` / `ResponseHeaderTimeout`. |
| `roundtripper.go` | transport caching rewritten (`transportFor` + `discardStash`, only the setup dial may cache, HTTP/2 dial deadline `http2RedialTimeout`, `sanitizeRawQuery`, per-scheme port in `getDialTLSAddr`, IDNA `dialHost`/`dialAddr`). |
| `connect.go` | SOCKS4 `DialContext` via goroutine+select; CONNECT deadline = min(client timeout, ctx deadline) with `context.AfterFunc` abort; HTTPS proxy dialled through `tls.Dialer{NetDialer: &c.Dialer}` so `WithDialer`'s Control hook runs. |
| `ja3.go` | `trust_anchors.BuildPayload` + `bytes.Clone` of the payload per handshake. |
| `racer.go` | winner's transport is cached instead of rebuilt; losers' responses/transports are discarded (`discardRaceResults`); `racingAttempts` constant. |
| `websocket_options.go` / `websocket.go` | `WithEnableCompression()` (permessage-deflate) wired to `EnableCompression`. |
| `utils.go` | `sanitizeRawQuery` / `isValidRawQueryByte`. |
| tests | upstream's own suite imported: `connect_deadlines_test.go`, `connect_headers_test.go`, `http2_ping_test.go`, `response_header_timeout_test.go`, `roundtripper_scheme_test.go`, `roundtripper_stash_test.go`, `tests/http2_redial_timeout_test.go`, `tests/chrome_trust_anchors_test.go`, `tests/testdata/chrome_root_store_v39.pb`, rewritten `tests/trust_anchors_test.go`/`tests/cookie_jar_test.go`/`tests/firefox_unsupported_group_test.go` (the last three are now hermetic httptest servers instead of live sites). |
| `example/` | upstream split the single `example/main.go` into per-feature subdirectories. The legacy local `example/main.go` is retained as an overlay (it is not built by CI). |
| `mise.toml`, `.github/workflows/build_workflow.yml` | Go pin 1.24.1 → 1.27.4 and `go-version`/`golang:1.27-alpine` accordingly — the new `go.mod` requires `go 1.27`. |

### Overlay points that had to be re-applied by hand

- `client.go`: the panic-to-error `do()`, the `mu sync.RWMutex` request/proxy
  lock, the debug-body fix (original bytes to the caller, decoded view only to
  the log) and the TCP-fingerprint wiring all survive; the two
  `newRoundTripper` call sites were re-pointed at
  `newRoundTripperWithPermute` **with upstream's new trailing
  `certificatePinner` and `timeout` arguments**.
  New in this sync: **`dialer.Control` is now chained, not replaced**
  (`chainTcpControl` in `tcp_fingerprint.go`). Overwriting it dropped the
  caller's `WithDialer` Control hook — socket tagging, fwmark, interface
  binding — which upstream's new `TestAnHTTPSProxyUsesTheConfiguredDialer`
  catches. The user hook runs first so its error aborts before any
  fingerprint option is applied.
- `roundtripper.go`: HTTP/3 construction stays split into
  `roundtripper_http3.go` and `http3.NextProtoH3` stays aliased as
  `nextProtoH3`. Upstream's rewritten caching (`transportFor`/`discardStash`)
  is taken as-is; the local `H2*` knobs are wired into the new
  `t2.SetT1(...)` block, and `newRoundTripperWithPermute` keeps the permuted
  `ClientHelloID`. **The protocol racer now receives `rt.clientHelloId`**
  (the permuted one), because upstream made the racer build its own HTTP/3
  transport — passing the raw profile ID would have silently disabled the
  per-handshake extension shuffle on every raced connection.
- `profiles/profiles.go`: the whole `TcpFingerprint` block, `IntPtr`/`BoolPtr`,
  `DefaultTcpFingerprints`, `clientToPlatform` and `GetTcpFingerprint` are
  intact, with upstream's new registry rows (chrome_154/154_PSK,
  safari_27_2) merged in and its deprecated `BuildTrustAnchorsPayload` shim
  added.
- `profiles/contributed_browser_profiles.go`: both additions kept —
  upstream's `Safari_27_2` and the local `Firefox_148`.
- `third_party/fhttp/` re-vendored to **v0.7.3** and the four engine patches
  rebuilt on the new source (see below).
- `roundtripper_setup_test.go`: re-synced to upstream (it calls
  `getTransport`, whose signature changed to return the stashed conn).

### `third_party/fhttp` overlay re-applied on v0.7.3

The vendored copy is pristine fhttp **v0.7.3** plus exactly four patches, each
marked `LOCAL PATCH` in the source:

1. `http2/hpack/encode.go`: `Encoder.SetIndexingDecision` +
   `IndexingChrome` (never index authorization / cookie / set-cookie /
   content-length / age).
2. `http2/transport.go`: `Transport.MaxDataFrameSize` (DATA-frame payload cap).
3. `http2/transport.go`: `Transport.PrefacePingIdleMs` (Chromium-style PING
   before the first HEADERS on an idle connection).
4. `http2/transport.go`: `Transport.DisablePriorityFrames` (suppresses
   `WritePriority` and the HEADERS PRIORITY flag).

v0.7.3 already ships `SetT1`, `ReadIdleTimeout`, `PingTimeout`,
`firstStreamID` and the `content-length`/`"gzip, deflate, br, zstd"`
corrections, so upstream's new `t2.SetT1(rt.buildHttp1Transport())` and the
transitive `ResponseHeaderTimeout` work unchanged.

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

The cache-key format is version 6. In addition to the ABI 2 / 2.1 fields, the
extension-order policy (`epm`/`epp`), PRIORITY-frame suppression (`hdpf`) and
the deep TCP fingerprint (`df`/`tos`/`nd`/`wc`/`ipid`) participate.
`header_order_by_dest`, `header_order_dest` and `cookie_crumb` are per-request
wire behaviour and are deliberately **not** keyed. Parity is pinned by
`python_tests/test_cache_key_parity.py` and
`cffi_binding/cachekey_parity_test.go` (TestCacheKeyParityWithPython) —
update BOTH sides together or these tests will fail.

**Format version 7 (2026-10-02)** removes `default_headers` (`~dh:`) from the
key. The profile default block is folded into the per-request headers by
`_merge_default_headers`, and the engine only reads the client-level copy when
`req.Header` is empty (`client.go`), which that merge makes unreachable. Keying
it minted one pooled `HttpClient` per unique block, so a per-request
`default_headers=` (or a rotating User-Agent) grew the pool until the cap
reclaimed it — measured at ~125 MB RSS after 3200 unique blocks versus ~53 MB
when the same workload varied a per-request header instead.
`connect_headers` (`~ch:`) **stays** keyed: the engine reads it at dial time for
the proxy CONNECT request, so it is genuine transport state. Pinned by
`test_unique_default_headers_do_not_grow_the_client_pool`.

**Format version 6 (2026-10-02)** appends the client-construction flags
`with_debug` (`dbg`) and `catch_panics` (`cp`). Both are passed to
`buildClientFromConfig`, and `with_debug` is not cosmetic: the debug path in
`client.go` *replaces* `resp.Body` with a charset-decoded copy, so the flag
decides what bytes a response body holds. Leaving them out of the key let a
pooled client built with one setting serve a request that asked for the other,
making the same request return different bytes depending on which session ran
first. The fields are emitted right after the ABI 3 block and before the
pseudo-header orders; the Go and Python emitters must stay in that order.

**ABI 4 (2026-11-12): upstream 1.18.1 transport health checks.**
`GetAbiVersion()` returns 4 and `RequestOptions` gained three appended ints:
`h2_read_idle_timeout_milliseconds`, `h2_ping_timeout_milliseconds`,
`response_header_timeout_milliseconds`. They map onto the new
`TransportOptions.ReadIdleTimeout` / `PingTimeout` / `ResponseHeaderTimeout`.
Python exposes them as `h2_read_idle_timeout_ms`, `h2_ping_timeout_ms` and
`response_header_timeout_ms` — session-level defaults plus per-request
overrides — and they degrade silently (no warning) on an ABI-3 library, since
omitting them only restores the older "no health check" behaviour.

Unlike the ABI 2 gate (which raises) and the ABI 3 gate (which warns), ABI 4
fields are absent from the struct entirely on an older library, so they are
simply not written; the Python wrapper keeps the CDEF append-only and the
struct layout check in `test_cdef_parity` verifies the tail.

The cache-key format is now **version 8**: ABI 4 appends
`|rit=<ms>|pit=<ms>|rht=<ms>` immediately after the version-6
`|dbg=…|cp=…` pair (both sides must be updated together —
`python_tests/test_cache_key_parity.py` and
`cffi_binding/cachekey_parity_test.go` pin the same vectors).

The binding also now calls `HttpClient.Close()` instead of
`CloseIdleConnections()` on pool eviction (TTL scan, LRU cap, explicit
`ClearClientPool`), so an evicted client releases its HTTP/3 UDP sockets and
reader goroutines instead of leaking them.

**ABI 2 (2026-09-12).** The bundled shared library exports `GetAbiVersion()`
(returning 3). `RequestOptions` gained `disable_session_tickets`,
`tls_keylog_path`, `root_ca_pem`, `root_ca_pem_len`; `CustomTlsClient` gained
`trust_anchors_payload`. Python's CDEF mirrors both. The Python wrapper
refuses ABI-2-only features against legacy (ABI 1) libraries.

## Dependency pruning (2026-11-12)

Three dependency paths brought code this project never executes into the shared
library.  Each is removed at its source rather than by a build flag, because
each was a correctness hazard as much as a size one.

| Removed | Size | Why it was dead |
| --- | --- | --- |
| stdlib HTTP client inside `cffi_binding/ech.go` | −711 KB | The ECH resolver used `net/http` for its DoH query and `encoding/json` for the answer. The DoH query now goes through `fhttp` (already linked, and the stack the whole project exists for), and the JSON envelope is read by `parseDoHResponse` — a scanner for exactly the RFC 8484 shape. That drops `net/http`, `net/http/internal/http2`, `net/http/httptrace`, `mime`, `crypto/x509` (the stdlib copy) and `encoding/asn1` from the link. Two HTTP stacks in one process was also the wrong shape: only fhttp carries the fingerprint behaviour. |
| `github.com/tam7t/hpkp` | −238 KB | It exists to parse RFC 7469 HPKP *response headers* — a mechanism browsers deleted in 2018. `pinner.go` used exactly two things: `base64(SHA256(RawSubjectPublicKeyInfo))` and a host→pins map with a subdomain walk. Both are now local (`pinStorage`, `certificateFingerprint`). Removing it also removed its `net/http` import, which was the last one. |
| `third_party/brotli/http.go` | included above | A server-side `HTTPCompressor` helper for `http.ResponseWriter`. Nothing calls it — the engine only ever uses `brotli.NewReader` to decompress. It imported `net/http`, so it kept the standard-library client stack alive after the ECH fix. |

Artifact: **15,016,072 → 14,070,664 bytes** on linux/amd64 (−6.3 %), which is
also below the pre-sync 1.16.0.7 binary (13,980,632 → still +0.6 %, explained by
ML-KEM/ML-DSA, zstd and the trust anchors; see the budget note in
`python_tests/test_binary_size_guard.py`).

New tests pinning the replacements: `cffi_binding/doh_parse_test.go`
(`TestParseDoHResponse`) and `pinner_test.go`
(`TestPinStorageSubdomainWalk`, `TestPinStorageLookupReturnsCopy`,
`TestCertificateFingerprintMatchesSpkiHash`). The pinner was also verified
end-to-end: a wrong pin still fails the handshake with `SSLError`.

### Measured and rejected

- **Two-level cache key ("split the invariant part, hash only the rest").**
  Measured first: `_compute_cache_key_hash` costs **6.0 µs** against a request
  total of ~1500 µs, i.e. **0.4 %**.  The number that made it look worth doing
  (590 µs, from cProfile) is profiler amplification: the function makes ~40
  f-string joins and dict lookups, and cProfile charges its own per-call
  overhead to each of them.  Re-timed with `time.perf_counter` around the real
  call it is 6 µs.  Splitting the key would need both hash implementations
  changed in lockstep for a 0.4 % gain, so it stays as it is.

  The same investigation produced the layer attribution worth keeping:

  | layer | µs |
  | --- | --- |
  | raw socket HTTP/1.1 keep-alive | 309 |
  | Go stdlib `net/http` | 743 |
  | this engine, plain Go, no headers | 851 |
  | this engine, plain Go, 13 real headers | 927 |
  | `NativeSession.get()` through CFFI | 1525 (p50 1209, min 606) |

  The gap between 927 and 1525 is **not** a fixed per-request cost: the
  minimum observed is 606 µs, below the plain-Go number, and the spread is
  localhost TCP jitter (p95 2959, max 10045).  cgo itself is 50 ns per call and
  161 ns per `C.GoString` — 73 of them per request is 12 µs.  Anything measured
  against localhost should be re-measured against a remote target before it is
  optimised.

- **x/text CJK encode tables (338 KB).** The linker keeps them under
  `-buildmode=c-shared` because external linking preserves the full
  `encoding.Encoding` interface itab. A pure-Go `go build .` from the same
  source links **0 bytes** of encode tables, so the source-side property
  `charset_lean.go` documents is real — it just does not reach the shipped
  artifact. Routing the decoder calls through a one-method interface was tried
  and changed nothing in the .so; the finding is recorded in that file so the
  next person does not repeat it. `-linkmode=internal` is not available:
  `c-shared` requires external linking.
- **go-brrr encoder tables (270 KB).** utls only calls `brrr.NewReader` (cert
  decompression), yet `internal/encoder` is still reachable through
  `PrepareDictionary`/error values, and its `static_dict.go` `init()` drags
  256 KB of packed dictionary hashes in. Cutting it means editing the internals
  of an upstream dependency's encoder, and removing the files does not compile
  (`hash2.go`/`hash10.go` reference them). Not worth the maintenance cost for
  270 KB.

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
| `test_cache_key_parity` | Python `_compute_cache_key_hash` ≡ Go `buildCacheKeyFromConfig` (format v7). Pinned vectors are mirrored in `cffi_binding/cachekey_parity_test.go`. |
| `test_cdef_parity` | `_core.py`'s CDEF struct layout ≡ the CDEF derived from `main.go`. |
| `test_export_parity` | Every symbol the CDEF declares is `//export`ed by every build variant's compiled files (and by each generated header, when fresh). |
| `test_session_signature_parity` | `AsyncSession.__init__` accepts exactly the same parameters as `Session.__init__`. |

Network-dependent fingerprint tests and the Windows C shared-library build
need their external services/toolchain and are tracked separately from the
offline compatibility checks above.
