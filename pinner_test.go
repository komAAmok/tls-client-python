package tls_client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"
)

// TestPinStorageSubdomainWalk pins the lookup semantics the hpkp replacement
// must preserve: an exact host wins, and a parent-domain rule applies only
// when that rule was registered with includeSubDomains.
func TestPinStorageSubdomainWalk(t *testing.T) {
	s := newPinStorage()

	s.add("example.com", pinRecord{sha256Pins: []string{"a"}, includeSubdomains: false})
	if got := s.lookup("example.com"); got == nil || got.sha256Pins[0] != "a" {
		t.Fatalf("exact host lookup failed: %+v", got)
	}
	if got := s.lookup("api.example.com"); got != nil {
		t.Fatalf("a non-includeSubdomains rule leaked to a subdomain: %+v", got)
	}

	s.add("corp.test", pinRecord{sha256Pins: []string{"b"}, includeSubdomains: true})
	for _, host := range []string{"corp.test", "a.corp.test", "x.y.corp.test"} {
		if got := s.lookup(host); got == nil || got.sha256Pins[0] != "b" {
			t.Fatalf("lookup(%q) = %+v, want the includeSubdomains rule", host, got)
		}
	}
	if got := s.lookup("unrelated.test"); got != nil {
		t.Fatalf("lookup of an unregistered host returned %+v", got)
	}
}

// TestPinStorageLookupReturnsCopy makes sure a caller cannot mutate the stored
// pins through the returned slice.
func TestPinStorageLookupReturnsCopy(t *testing.T) {
	s := newPinStorage()
	s.add("h.test", pinRecord{sha256Pins: []string{"a"}, includeSubdomains: false})

	first := s.lookup("h.test")
	first.sha256Pins[0] = "mutated"
	if got := s.lookup("h.test"); got.sha256Pins[0] != "a" {
		t.Fatalf("the stored pins were mutated through the lookup result: %+v", got)
	}
}

// TestCertificateFingerprintMatchesSpkiHash pins the fingerprint format: the
// base64 of SHA256 over RawSubjectPublicKeyInfo, which is what the hpkp-pins
// tool prints and what an operator pastes into WithCertificatePinning.  It
// runs against a real generated certificate so the RawSubjectPublicKeyInfo
// field is populated the way it is on the wire.
func TestCertificateFingerprintMatchesSpkiHash(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pinner.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	want := base64.StdEncoding.EncodeToString(sum[:])
	got := certificateFingerprint(cert)

	if got != want {
		t.Fatalf("certificateFingerprint = %q, want %q", got, want)
	}
	if len(got) != 44 {
		t.Fatalf("a SHA256 pin is 44 base64 chars, got %d: %q", len(got), got)
	}

	// And the pin must actually satisfy the storage match used by Pin().
	storage := newPinStorage()
	storage.add("pinner.test", pinRecord{sha256Pins: []string{got}})
	record := storage.lookup("pinner.test")
	if record == nil || record.sha256Pins[0] != got {
		t.Fatalf("the computed pin does not round-trip through the storage")
	}
}
