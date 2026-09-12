//go:build tls_lite

package main

import "C"

// Lite build: ECH-over-DoH resolution is excluded (it needs net/http).
// ResolveECHConfig returns nil in the lite variant; users can still supply
// ech_candidate_payloads manually through custom_tls_client.
//
// The symbol MUST keep the exported name and the //export directive: the
// CDEF hand-written in tls_client/_core.py declares ResolveECHConfig for
// every variant, so omitting it here makes dlopen/cdef fail on a lite
// build rather than letting tls_client.ech.resolve() return None as its
// docstring promises.
//
//export ResolveECHConfig
func ResolveECHConfig(host *C.char) *C.char {
	return nil
}
