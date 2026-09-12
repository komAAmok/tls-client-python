package profiles

import (
	"os"
	"testing"
)

// snapshotMappedTLSClients returns a copy of MappedTLSClients so a test can
// restore the global table after mutating it.
func snapshotMappedTLSClients() map[string]ClientProfile {
	snapshot := make(map[string]ClientProfile, len(MappedTLSClients))
	for name, profile := range MappedTLSClients {
		snapshot[name] = profile
	}
	return snapshot
}

func restoreMappedTLSClients(snapshot map[string]ClientProfile) {
	for name := range MappedTLSClients {
		delete(MappedTLSClients, name)
	}
	for name, profile := range snapshot {
		MappedTLSClients[name] = profile
	}
}

// TestNanoProfileFilterUnsetIsNoOp verifies an empty/unset environment leaves
// the full profile catalogue intact — a stock build must be unaffected.
func TestNanoProfileFilterUnsetIsNoOp(t *testing.T) {
	before := snapshotMappedTLSClients()
	defer restoreMappedTLSClients(before)

	t.Setenv(nanoProfilesEnv, "")
	if got := ApplyNanoProfileFilter(); got != len(before) {
		t.Fatalf("empty filter changed the catalogue: %d → %d", len(before), got)
	}
	if len(MappedTLSClients) != len(before) {
		t.Fatal("empty filter mutated MappedTLSClients")
	}
}

// TestNanoProfileFilterTrims verifies only the named identifiers survive.
func TestNanoProfileFilterTrims(t *testing.T) {
	before := snapshotMappedTLSClients()
	defer restoreMappedTLSClients(before)

	// Pick two identifiers that are guaranteed to exist and are not the
	// engine default, so the "default is preserved" rule is also exercised.
	keep := []string{"chrome_133", "chrome_150"}
	for _, name := range keep {
		if _, ok := MappedTLSClients[name]; !ok {
			t.Skipf("profile %q not registered in this build", name)
		}
	}

	t.Setenv(nanoProfilesEnv, "chrome_133")
	ApplyNanoProfileFilter()

	if _, ok := MappedTLSClients["chrome_133"]; !ok {
		t.Fatal("requested profile chrome_133 was dropped")
	}
	if _, ok := MappedTLSClients["chrome_99"]; ok {
		t.Fatal("unrequested profile chrome_99 survived the nano filter")
	}

	// The engine's default profile must always remain selectable.
	defaultName := identifierForProfile(DefaultClientProfile)
	if defaultName == "" {
		t.Fatal("could not resolve the default profile's identifier")
	}
	if _, ok := MappedTLSClients[defaultName]; !ok {
		t.Fatalf("default profile %q was dropped by the nano filter", defaultName)
	}
}

// TestNanoProfileFilterUnknownNameIsIgnored verifies a typo does not panic and
// still leaves the table in a usable state.
func TestNanoProfileFilterUnknownNameIsIgnored(t *testing.T) {
	before := snapshotMappedTLSClients()
	defer restoreMappedTLSClients(before)

	// Silence the warning the filter prints for the bogus name.
	stderr := os.Stderr
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err == nil {
		os.Stderr = devNull
		defer func() { os.Stderr = stderr; devNull.Close() }()
	}

	t.Setenv(nanoProfilesEnv, "definitely_not_a_profile")
	if got := ApplyNanoProfileFilter(); got == 0 {
		t.Fatal("nano filter left an empty catalogue")
	}
	if _, ok := MappedTLSClients[identifierForProfile(DefaultClientProfile)]; !ok {
		t.Fatal("default profile was dropped when only a bogus name was given")
	}
}

// TestIdentifierForProfileFindsDefault guards the helper the nano filter leans
// on for the "never drop the default" guarantee.
func TestIdentifierForProfileFindsDefault(t *testing.T) {
	if got := identifierForProfile(DefaultClientProfile); got == "" {
		t.Fatal("identifierForProfile could not resolve the default profile")
	}
}
