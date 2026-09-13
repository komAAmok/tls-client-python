package main

import (
	"bytes"
	"testing"
)

// TestExtractECHFromRDATA validates the HTTPS-RR SvcParam parser against a
// hand-built wire record:
//
//	priority=1, qname="peet.ws" root-terminated,
//	alpn (key 0) "h3", ech (key 4) = deadbeef
func TestExtractECHFromRDATA(t *testing.T) {
	// Build the wire record programmatically:
	var r []byte
	r = append(r, 0x00, 0x01)                     // priority
	r = append(r, 4, 'p', 'e', 'e', 't')          // label
	r = append(r, 2, 'w', 's')                    // label
	r = append(r, 0)                              // root label
	// alpn param: key 0x0000, len 2, "h3"
	r = append(r, 0x00, 0x00, 0x00, 0x02, 'h', '3')
	// ech param: key 0x0004, len 4, deadbeef
	r = append(r, 0x00, 0x04, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef)

	got := extractECHFromRDATA(r)
	if !bytes.Equal(got, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("ech param mismatch: %x", got)
	}

	// Record without an ech param → nil
	var noECH []byte
	noECH = append(noECH, 0x00, 0x01)
	noECH = append(noECH, 0)
	noECH = append(noECH, 0x00, 0x00, 0x00, 0x02, 'h', '3')
	if got := extractECHFromRDATA(noECH); got != nil {
		t.Fatalf("expected nil, got %x", got)
	}

	// Truncated ech value → nil (no panic)
	var trunc []byte
	trunc = append(trunc, 0x00, 0x01)
	trunc = append(trunc, 0)
	trunc = append(trunc, 0x00, 0x04, 0x00, 0x10, 0xaa)
	if got := extractECHFromRDATA(trunc); got != nil {
		t.Fatalf("expected nil for truncated record, got %x", got)
	}
}
