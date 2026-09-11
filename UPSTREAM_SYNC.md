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
- `cffi_src/factory.go`, `cffi_src/types.go`: TCP/IP fingerprint fields and the
  local cookie-jar construction behavior.
- `example/main.go`: retained legacy local example; upstream split examples
  into subdirectories.
- `tests/client_test.go`, `tests/client_test_utils.go`,
  `tests/header_order_test.go`, and related test files: local BrowserLeaks
  endpoint adaptation.
- `.gitignore` and `Readme.md`: union/local project versions, respectively.

## Python binary ABI boundary

The bundled native libraries were built from the pre-sync local CFFI ABI.
Therefore `tls_client/`, the C declarations in `cffi_binding/`, the package
version (`1.15.1.1`), and Python's advertised profile list remain unchanged in
this sync. This preserves compatibility with the shipped binaries.

The one source-only compatibility edit in `cffi_binding/main.go` passes an
empty `trustAnchorsPayload` argument to the expanded upstream Go API. Do not
expose `disable_session_tickets`, `trust_anchors_payload`, `chrome_152`, or
`chrome_152_PSK` in Python until all bundled libraries are rebuilt together
from this source and the C struct ABI is versioned or updated atomically.

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
