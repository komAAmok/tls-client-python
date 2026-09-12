package tls_client

import (
	"crypto/rand"
	"encoding/binary"
	mrand "math/rand"

	tls "github.com/bogdanfinn/utls"
)

// ExtensionPermuteMode selects how the TLS extension order is varied between
// handshakes.
//
// Chromium does not send one fixed order: since Chrome 106 it permutes the
// order of most extensions once per handshake, keeping GREASE, padding and
// pre_shared_key positionally invariant.  A client that always sends the same
// order therefore has a fingerprint that no real browser produces.
type ExtensionPermuteMode int

const (
	// PermuteOff sends the captured order unchanged.  This is the byte-exact
	// capture order and is what a single pinned fingerprint wants.
	PermuteOff ExtensionPermuteMode = iota
	// PermuteChrome matches Chromium: every extension except GREASE, padding
	// and pre_shared_key is shuffled with a fresh unseeded source per call.
	PermuteChrome
	// PermuteAll shuffles every extension, including padding.  GREASE and
	// pre_shared_key stay pinned because their position is semantically
	// significant (GREASE must lead the list; PSK must be last).
	PermuteAll
	// PermutePrefix shuffles only the first N extensions (see
	// ExtensionPermutePrefix) and leaves the tail in capture order.  This
	// reproduces captures where only the leading extension block rotates.
	PermutePrefix
)

// extensionPermuteConfig carries the permutation policy for one client.
type extensionPermuteConfig struct {
	mode   ExtensionPermuteMode
	prefix int
}

// permuteExtensions applies the configured order policy to a copy of exts.
// It never mutates the caller's slice, so a shared ClientProfile stays intact
// across connections.
func permuteExtensions(exts []tls.TLSExtension, cfg extensionPermuteConfig) []tls.TLSExtension {
	if cfg.mode == PermuteOff || len(exts) == 0 {
		return exts
	}

	out := make([]tls.TLSExtension, len(exts))
	copy(out, exts)

	limit := len(out)
	if cfg.mode == PermutePrefix {
		if cfg.prefix <= 0 || cfg.prefix >= len(out) {
			return out
		}
		limit = cfg.prefix
	}

	shuffleSpan(out[:limit], cfg.mode == PermuteAll)

	return out
}

// shuffleSpan shuffles exts in place using a fresh, unseeded-per-call source.
//
// GREASE and pre_shared_key are always pinned.  Padding is pinned unless
// includePadding is set: Chromium keeps padding last, which is why it is
// excluded by default.
func shuffleSpan(exts []tls.TLSExtension, includePadding bool) {
	if len(exts) < 2 {
		return
	}

	pinned := func(e tls.TLSExtension) bool {
		switch e.(type) {
		case *tls.UtlsGREASEExtension, tls.PreSharedKeyExtension:
			return true
		case *tls.UtlsPaddingExtension:
			return !includePadding
		}
		return false
	}

	// Draw a fresh 64-bit seed for every handshake.  A shared, seeded source
	// would make two connections from one process send the same order, which
	// is itself detectable; crypto/rand cannot repeat across processes.
	var seedBytes [8]byte
	if _, err := rand.Read(seedBytes[:]); err != nil {
		// crypto/rand failing is fatal for the handshake anyway; fall back to
		// the runtime source rather than sending a constant order.
		mrand.Shuffle(len(exts), func(i, j int) {
			if pinned(exts[i]) || pinned(exts[j]) {
				return
			}
			exts[i], exts[j] = exts[j], exts[i]
		})
		return
	}
	seed := int64(binary.LittleEndian.Uint64(seedBytes[:]))

	mrand.New(mrand.NewSource(seed)).Shuffle(len(exts), func(i, j int) {
		if pinned(exts[i]) || pinned(exts[j]) {
			return
		}
		exts[i], exts[j] = exts[j], exts[i]
	})
}

// applyExtensionPermute wraps a ClientHelloID so that every spec it builds has
// the configured extension-order policy applied.  The returned ID can be used
// anywhere the original was, including by utls.UClient.
//
// The wrapper is a no-op when permute is off or when there is no inner
// factory, so callers can apply it unconditionally.
func applyExtensionPermute(id tls.ClientHelloID, cfg extensionPermuteConfig) tls.ClientHelloID {
	if cfg.mode == PermuteOff || id.SpecFactory == nil {
		return id
	}

	inner := id.SpecFactory
	id.SpecFactory = func() (tls.ClientHelloSpec, error) {
		spec, err := inner()
		if err != nil {
			return spec, err
		}
		spec.Extensions = permuteExtensions(spec.Extensions, cfg)
		return spec, nil
	}
	return id
}
