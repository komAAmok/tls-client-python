package profiles

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// nanoProfilesEnv selects the profiles retained by a size-trimmed ("nano")
// build.  When set (a comma-separated identifier list), a post-init pass drops
// every other entry from MappedTLSClients so a scrape-only deployment ships
// only the fingerprints it actually names.  Empty/unset keeps the full table.
const nanoProfilesEnv = "TLS_CLIENT_NANO_PROFILES"

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

// identifierForProfile returns the MappedTLSClients key whose ClientHelloID
// identifier fields equal those of *target*, preferring the shortest
// (non-PSK) name.  Returns "" when the profile is not registered.
//
// ClientHelloID is not comparable as a struct (its SpecFactory field is an
// interface), so the comparison is done field by field on the plain string
// and Client fields that actually identify a profile.
func identifierForProfile(target ClientProfile) string {
	want := target.GetClientHelloId()
	best := ""
	for name, profile := range MappedTLSClients {
		got := profile.GetClientHelloId()
		if got.Client != want.Client || got.Version != want.Version {
			continue
		}
		if best == "" || len(name) < len(best) {
			best = name
		}
	}
	return best
}

// ApplyNanoProfileFilter trims MappedTLSClients down to the identifiers named
// in the TLS_CLIENT_NANO_PROFILES environment variable.
//
// It is a no-op when the variable is empty/unset, so a full or lite build is
// unaffected.  Unknown identifiers are ignored (with a warning on stderr)
// rather than treated as fatal: the environment variable is a deployment
// knob, not a correctness contract.
//
// main() calls this once at startup, after the init() registrations have run.
func ApplyNanoProfileFilter() int {
	raw := strings.TrimSpace(os.Getenv(nanoProfilesEnv))
	if raw == "" {
		return len(MappedTLSClients)
	}

	keep := make(map[string]struct{})
	for _, name := range strings.Split(raw, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		keep[name] = struct{}{}
	}

	// Preserve the identifier the engine falls back to, so a nano build can
	// never strand a request that omitted client_identifier.
	if name := identifierForProfile(DefaultClientProfile); name != "" {
		keep[name] = struct{}{}
	}

	for name := range MappedTLSClients {
		if _, ok := keep[name]; ok {
			continue
		}
		delete(MappedTLSClients, name)
	}

	// Warn about identifiers the caller asked for but that do not exist, so a
	// typo surfaces without silently shrinking the build further.
	for name := range keep {
		if _, ok := MappedTLSClients[name]; !ok {
			fmt.Fprintf(os.Stderr,
				"profiles: nano build requested unknown profile %q; ignored\n", name)
		}
	}

	return len(MappedTLSClients)
}
