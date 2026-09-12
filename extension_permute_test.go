package tls_client

import (
	"testing"

	tls "github.com/bogdanfinn/utls"
)

func sampleExtensions() []tls.TLSExtension {
	return []tls.TLSExtension{
		&tls.UtlsGREASEExtension{},
		&tls.SNIExtension{},
		&tls.ExtendedMasterSecretExtension{},
		&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
		&tls.SupportedCurvesExtension{Curves: []tls.CurveID{tls.X25519}},
		&tls.SupportedPointsExtension{SupportedPoints: []byte{tls.PointFormatUncompressed}},
		&tls.SessionTicketExtension{},
		&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.PSSWithSHA256}},
		&tls.SCTExtension{},
		&tls.KeyShareExtension{KeyShares: []tls.KeyShare{{Group: tls.X25519}}},
		&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
		&tls.SupportedVersionsExtension{Versions: []uint16{tls.VersionTLS13}},
		&tls.ALPNExtension{AlpnProtocols: []string{"h2"}},
		&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
	}
}

func TestPermuteOffKeepsOrder(t *testing.T) {
	in := sampleExtensions()
	out := permuteExtensions(in, extensionPermuteConfig{mode: PermuteOff})

	for i := range in {
		if in[i] != out[i] {
			t.Fatalf("PermuteOff reordered extension %d", i)
		}
	}
}

func TestPermuteChromeDoesNotMutateInput(t *testing.T) {
	in := sampleExtensions()
	snapshot := make([]tls.TLSExtension, len(in))
	copy(snapshot, in)

	_ = permuteExtensions(in, extensionPermuteConfig{mode: PermuteChrome})

	for i := range snapshot {
		if snapshot[i] != in[i] {
			t.Fatalf("permuteExtensions mutated the caller slice at %d", i)
		}
	}
}

func TestPermuteChromePinsGreaseAndPadding(t *testing.T) {
	in := sampleExtensions()

	for i := 0; i < 32; i++ {
		out := permuteExtensions(in, extensionPermuteConfig{mode: PermuteChrome})

		if _, ok := out[0].(*tls.UtlsGREASEExtension); !ok {
			t.Fatalf("iteration %d: GREASE moved from the head", i)
		}
		if _, ok := out[len(out)-1].(*tls.UtlsPaddingExtension); !ok {
			t.Fatalf("iteration %d: padding moved from the tail", i)
		}
	}
}

func TestPermuteChromeIsFreshPerCall(t *testing.T) {
	in := sampleExtensions()

	// Identify each extension by the address of its interface value's target,
	// which is unique per element of the input slice.
	label := make(map[tls.TLSExtension]string, len(in))
	for i, e := range in {
		label[e] = string(rune('A' + i))
	}

	// The chance of two independent permutations of 12 movable elements
	// matching is astronomically small; require at least two distinct orders
	// across 16 draws.
	seen := make(map[string]struct{})
	for i := 0; i < 16; i++ {
		out := permuteExtensions(in, extensionPermuteConfig{mode: PermuteChrome})

		key := ""
		for _, e := range out {
			key += label[e]
		}
		seen[key] = struct{}{}
	}

	if len(seen) < 2 {
		t.Fatalf("PermuteChrome produced only %d distinct order(s) across 16 calls", len(seen))
	}
}

func TestPermutePrefixRestrictsSpan(t *testing.T) {
	in := sampleExtensions()
	const prefix = 4

	out := permuteExtensions(in, extensionPermuteConfig{mode: PermutePrefix, prefix: prefix})

	// GREASE sits first and is pinned, so index 0 is stable; the tail beyond
	// the prefix must be byte-identical to the input.
	for i := prefix; i < len(in); i++ {
		if in[i] != out[i] {
			t.Fatalf("PermutePrefix changed index %d beyond the prefix", i)
		}
	}
}
