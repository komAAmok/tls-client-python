//go:build darwin

package tls_client

import "testing"

func TestSetMSSIsBestEffortBeforeConnect(t *testing.T) {
	// net.Dialer.Control runs before connect. Darwin rejects TCP_MAXSEG there,
	// so a valid MSS hint must be ignored rather than aborting the request.
	if err := setMSS(-1, 1460); err != nil {
		t.Fatalf("setMSS returned an error on darwin: %v", err)
	}
}

func TestSetMSSStillValidatesInput(t *testing.T) {
	if err := setMSS(-1, 0); err == nil {
		t.Fatal("setMSS accepted an invalid MSS")
	}
}

