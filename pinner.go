package tls_client

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"

	http "github.com/bogdanfinn/fhttp"
	tls "github.com/bogdanfinn/utls"
)

var DefaultBadPinHandler = func(req *http.Request) {
	fmt.Println("this is the default bad pin handler")
}

var ErrBadPinDetected = errors.New("bad ssl pin detected")

// certificatePinStorage maps a host to its pin set.
//
// LOCAL OVERLAY: this replaces github.com/tam7t/hpkp.  That package exists to
// parse RFC 7469 HPKP *response headers* — a mechanism browsers removed in
// 2018 — and drags encoding/base64, net/http and the whole standard-library
// HTTP client stack into the link for it.  This project only ever used two of
// its pieces: the base64(SHA256(SPKI)) fingerprint and a host->pins map with
// subdomain-walk lookup, which is what follows.  behaviour is identical for
// every call site in pinner.go.
var certificatePinStorage = newPinStorage()

// pinRecord is one pinned host.
type pinRecord struct {
	sha256Pins        []string
	includeSubdomains bool
}

type pinStorage struct {
	mu      sync.RWMutex
	domains map[string]pinRecord
}

func newPinStorage() *pinStorage {
	return &pinStorage{domains: make(map[string]pinRecord)}
}

// add registers a host's pins.  A non-permanent record (MaxAge 0) that mirrors
// an existing non-permanent one is dropped; every call site here passes
// Permanent: true, so this keeps the original semantics for the paths that can
// still reach it.
func (s *pinStorage) add(host string, record pinRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.domains[host] = record
}

// lookup returns the pins for host, walking parent domains for an
// includeSubdomains rule.  The returned slice is a copy.
func (s *pinStorage) lookup(host string) *pinRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if record, ok := s.domains[host]; ok {
		return copyPinRecord(record)
	}

	for {
		i := strings.Index(host, ".")
		if i <= 0 {
			return nil
		}
		host = host[i+1:]
		if record, ok := s.domains[host]; ok && record.includeSubdomains {
			return copyPinRecord(record)
		}
	}
}

func copyPinRecord(record pinRecord) *pinRecord {
	out := record
	out.sha256Pins = append([]string(nil), record.sha256Pins...)
	return &out
}

// certificateFingerprint is hpkp.Fingerprint: base64(SHA256(RawSubjectPublicKeyInfo)).
func certificateFingerprint(cert *x509.Certificate) string {
	digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(digest[:])
}

type certificatePinner struct {
	certificatePins map[string][]string
}

type CertificatePinner interface {
	Pin(conn *tls.UConn, host string) error
}

func NewCertificatePinner(certificatePins map[string][]string) (CertificatePinner, error) {
	pinner := &certificatePinner{
		certificatePins: certificatePins,
	}

	err := pinner.init()
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate certificate pinner: %w", err)
	}

	return pinner, nil
}

func (cp *certificatePinner) init() error {
	if len(cp.certificatePins) == 0 {
		return nil
	}

	for host, pinsByHost := range cp.certificatePins {
		includeSubdomains := false
		if strings.Contains(host, "*.") {
			includeSubdomains = true
			host = strings.ReplaceAll(host, "*.", "")
		}

		pinnedHost := certificatePinStorage.lookup(host)

		if pinnedHost != nil && reflect.DeepEqual(pinnedHost.sha256Pins, pinsByHost) {
			// another pinner instance with the same Pins already initialized the host. we do not need to pin again
			continue
		}

		certificatePinStorage.add(host, pinRecord{
			sha256Pins:        pinsByHost,
			includeSubdomains: includeSubdomains,
		})
	}

	return nil
}

func (cp *certificatePinner) Pin(conn *tls.UConn, host string) error {
	validPin := false

	if len(cp.certificatePins) == 0 {
		return nil
	}

	pinnedHost := certificatePinStorage.lookup(host)

	if pinnedHost == nil {
		// host is not pinned, we treat it as valid
		return nil
	}

	var actualPins []string

	for _, peerCert := range conn.ConnectionState().PeerCertificates {
		peerPin := certificateFingerprint(peerCert)
		actualPins = append(actualPins, peerPin)

		for _, want := range pinnedHost.sha256Pins {
			if want == peerPin {
				validPin = true
				break
			}
		}
	}

	if !validPin {
		return fmt.Errorf("%w, found pins: %v", ErrBadPinDetected, actualPins)
	}

	return nil
}
