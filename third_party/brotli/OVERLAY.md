# Vendored brotli — local overlay

Source: `github.com/andybalholm/brotli v1.2.7`, unmodified except for the
single deletion below.  Wired in through `replace github.com/andybalholm/brotli
=> ./third_party/brotli` in the root `go.mod`.

## Deleted: `http.go`

That file is a **server-side** helper (`HTTPCompressor` / `HTTPCompressorWithLevel`
for `http.ResponseWriter`).  Nothing in this project calls it, and nothing in
`third_party/fhttp` does either — the engine only ever uses `brotli.NewReader`
and `brotli.Reader` to *decompress* a response body.

It is deleted because it is sufficient on its own to link the entire
standard-library HTTP client stack: importing `net/http` pulls `crypto/x509`,
`encoding/asn1`, `mime`, `net/http/internal/http2`, `vendor/golang.org/x/net/http2/hpack`
and `net/http/httptrace` into a binary that otherwise has no use for any of
them.  Measured on linux/amd64: see the size table in `UPSTREAM_SYNC.md`.

Keeping the file would also be a correctness trap rather than a size one: two
HTTP stacks in one process, one of them (fhttp) carrying the fingerprint
behaviour this project exists for.
