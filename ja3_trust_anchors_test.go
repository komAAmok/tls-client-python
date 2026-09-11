package tls_client

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	tls "github.com/bogdanfinn/utls"
)

// A Chrome 152 capture, shortened to four anchors. The payload starts with the
// 16-bit list length, then an 8-bit length and an ID per anchor.
const testTrustAnchorsCapture = "001904d67909010582df13020604d679090a08839a648c9b2d0107"

func trustAnchorsJa3(withExtension bool) string {
	extensions := "0-23-65281-10-11-16-5-13-18-51-45-43-27"
	if withExtension {
		extensions += "-51764"
	}

	return fmt.Sprintf("771,4865-4866-4867-49195-49199,%s,29-23-24,0", extensions)
}

func buildSpec(t *testing.T, ja3, trustAnchorsPayload string) (tls.ClientHelloSpec, error) {
	t.Helper()

	factory, err := GetSpecFactoryFromJa3String(
		ja3,
		[]string{"ECDSAWithP256AndSHA256"}, nil, []string{"1.3", "1.2"},
		[]string{"X25519"}, []string{"h2", "http/1.1"}, []string{"h2"},
		nil, nil, []string{"brotli"}, 0, trustAnchorsPayload,
	)
	if err != nil {
		return tls.ClientHelloSpec{}, err
	}

	return factory()
}

func findTrustAnchors(spec tls.ClientHelloSpec) *tls.GenericExtension {
	for _, ext := range spec.Extensions {
		if generic, ok := ext.(*tls.GenericExtension); ok && generic.Id == extensionTrustAnchors {
			return generic
		}
	}

	return nil
}

// TestJa3TrustAnchors_PayloadIsSent covers the case a Chrome 144+ fingerprint
// needs: the ja3 string names extension 51764 and the payload comes alongside
// it, because a ja3 string carries extension IDs but no extension data.
func TestJa3TrustAnchors_PayloadIsSent(t *testing.T) {
	spec, err := buildSpec(t, trustAnchorsJa3(true), testTrustAnchorsCapture)
	if err != nil {
		t.Fatalf("building the spec: %v", err)
	}

	extension := findTrustAnchors(spec)
	if extension == nil {
		t.Fatal("the spec does not contain the trust_anchors extension")
	}

	capture, err := hex.DecodeString(testTrustAnchorsCapture)
	if err != nil {
		t.Fatal(err)
	}

	// The anchor order is redrawn, so the bytes may differ, but the payload has
	// to stay the same size and keep its length field consistent.
	if len(extension.Data) != len(capture) {
		t.Fatalf("payload length: want %d, got %d", len(capture), len(extension.Data))
	}

	listLen := int(extension.Data[0])<<8 | int(extension.Data[1])
	if listLen != len(extension.Data)-2 {
		t.Fatalf("length field %d does not match the %d byte list", listLen, len(extension.Data)-2)
	}
}

// TestJa3TrustAnchors_MissingPayloadExplainsItself makes sure the error names
// the field to set instead of the bare "unknown extension" the generic path
// would produce.
func TestJa3TrustAnchors_MissingPayloadExplainsItself(t *testing.T) {
	_, err := buildSpec(t, trustAnchorsJa3(true), "")
	if err == nil {
		t.Fatal("expected an error when the ja3 asks for trust_anchors without a payload")
	}

	if !strings.Contains(err.Error(), "trustAnchorsPayload") {
		t.Fatalf("the error should name the field to set, got: %v", err)
	}
}

// TestJa3TrustAnchors_NotRequested covers that the extension is only added when
// the ja3 string asks for it, so a payload left over in a config does not change
// the fingerprint on its own.
func TestJa3TrustAnchors_NotRequested(t *testing.T) {
	spec, err := buildSpec(t, trustAnchorsJa3(false), testTrustAnchorsCapture)
	if err != nil {
		t.Fatalf("building the spec: %v", err)
	}

	if findTrustAnchors(spec) != nil {
		t.Fatal("trust_anchors was sent although the ja3 string does not list it")
	}
}

// TestJa3TrustAnchors_MalformedPayload covers that a bad capture fails when the
// factory is built rather than silently producing a wrong ClientHello.
func TestJa3TrustAnchors_MalformedPayload(t *testing.T) {
	for name, payload := range map[string]string{
		"not hex":            "zzzz",
		"shorter than field": "00",
		"length mismatch":    "00ff04d67909",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := buildSpec(t, trustAnchorsJa3(true), payload); err == nil {
				t.Fatal("expected an error for a malformed trust anchors payload")
			}
		})
	}
}

// TestJa3TrustAnchors_EmptyList covers the payload the Chrome 144 and 146
// profiles send: a list with no anchors in it.
func TestJa3TrustAnchors_EmptyList(t *testing.T) {
	spec, err := buildSpec(t, trustAnchorsJa3(true), "0000")
	if err != nil {
		t.Fatalf("building the spec: %v", err)
	}

	extension := findTrustAnchors(spec)
	if extension == nil {
		t.Fatal("the spec does not contain the trust_anchors extension")
	}

	if len(extension.Data) != 2 || extension.Data[0] != 0 || extension.Data[1] != 0 {
		t.Fatalf("want an empty anchor list, got %x", extension.Data)
	}
}
