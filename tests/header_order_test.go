package tests

import (
	"testing"
)

// ── Header order tests ──────────────────────────────────────────────────────
// These tests verify that custom HTTP header orders are respected by the client.
// Currently skipped because browserleaks.com/json does not expose HTTP/2
// frame-level or HTTP/1 header order data.  Re-enable when targeting an echo
// server or tls.peet.ws/api/all that returns this level of detail.

func TestClient_HeaderOrder(t *testing.T) {
	t.Skip("browserleaks.com/json does not expose HTTP/2 frame-level header order data")
}

func TestClient_HeaderOrderHttp1(t *testing.T) {
	t.Skip("browserleaks.com/json does not expose HTTP/1 header order data")
}

func TestClient_HeaderOrderWithContentLengthHttp1(t *testing.T) {
	t.Skip("browserleaks.com/json does not expose HTTP/1 header order data")
}

func TestClient_HeaderOrderWithContentLength(t *testing.T) {
	t.Skip("browserleaks.com/json does not expose HTTP/2 frame-level header order data")
}
