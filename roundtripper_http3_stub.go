//go:build tls_lite

package tls_client

import (
	"errors"

	http "github.com/bogdanfinn/fhttp"
)

// Lite build: QUIC/HTTP-3 (github.com/bogdanfinn/quic-go-utls) and the
// SOCKS5-UDP QUIC dialer are excluded to keep the shared library small.
// Requesting an HTTP/3 transport in this variant returns a clear error;
// callers should set disable_http3 (the Python wrapper does this
// automatically for the lite variant).
const nextProtoH3 = "h3"

const BuildVariant = "lite"

func buildHTTP3Transport(cfg *http3Config) (http.RoundTripper, error) {
	return nil, errors.New("tls-client: HTTP/3 is not available in the lite build (built without QUIC); use disable_http3 or the full build")
}

func profileDefaultMaxResponseHeaderBytes(cfg *http3Config) int {
	return -1
}
