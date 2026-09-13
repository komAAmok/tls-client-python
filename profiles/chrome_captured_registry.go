package profiles

import (
	"fmt"
	"sort"
)

// errUnknownChromeCapture reports a Chrome major version that has no recorded
// capture.  The generated table in chrome_captured_profiles.go is the source
// of truth for the supported range.
func errUnknownChromeCapture(major int) error {
	return fmt.Errorf(
		"profiles: no Chrome capture for major version %d (supported: %d..%d)",
		major, chromeCapturedMajors[0], chromeCapturedMajors[len(chromeCapturedMajors)-1],
	)
}

// init registers every captured Chrome profile into MappedTLSClients under
// both the plain and the PSK identifier, so `chrome_99` .. `chrome_153` are
// selectable exactly like the hand-written profiles.
//
// A captured profile replaces an existing entry only when that entry was not
// already customised by hand: the hand-written profiles for the newest
// versions stay authoritative so their PSK and trust-anchor refinements are
// preserved, while versions that were previously missing become available.
func init() {
	for _, major := range chromeCapturedMajors {
		profile, ok := CapturedChromeProfile(major)
		if !ok {
			continue
		}

		plain := fmt.Sprintf("chrome_%d", major)
		if _, exists := MappedTLSClients[plain]; !exists {
			MappedTLSClients[plain] = profile
		}

		psk := fmt.Sprintf("chrome_%d_PSK", major)
		if _, exists := MappedTLSClients[psk]; !exists {
			// Register the captured profile unchanged under the PSK name.
			// The captured ClientHello already lists its extensions in
			// captured order with a real pre_shared_key, so no PSK-specific
			// rewriting is needed here (the hand-written profiles in
			// profiles.go carry those refinements for the newest versions).
			MappedTLSClients[psk] = profile
		}
	}
}

// CapturedChromeProfileNames returns the generated identifier names, sorted.
func CapturedChromeProfileNames() []string {
	names := make([]string, 0, len(chromeCapturedMajors))
	for _, major := range chromeCapturedMajors {
		names = append(names, fmt.Sprintf("chrome_%d", major))
	}
	sort.Strings(names)
	return names
}
