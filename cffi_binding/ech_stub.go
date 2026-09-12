//go:build tls_lite

package main

import "C"

// Lite build: ECH-over-DoH resolution is excluded (it needs net/http).
// ResolveECHConfig returns nil in the lite variant; users can still supply
// ech_candidate_payloads manually through custom_tls_client.

func resolveECHConfigLite(host *C.char) *C.char {
	return nil
}
