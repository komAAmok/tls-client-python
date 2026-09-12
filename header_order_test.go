package tls_client

import (
	"testing"

	http "github.com/bogdanfinn/fhttp"
)

func TestHeaderOrderForDestNavigationStartsWithClientHints(t *testing.T) {
	order := HeaderOrderForDest("chrome", "document")
	if len(order) == 0 {
		t.Fatal("no order returned for chrome navigations")
	}
	if order[0] != "sec-ch-ua" {
		t.Fatalf("navigation should lead with sec-ch-ua, got %q", order[0])
	}
	if order[len(order)-1] != "cookie" {
		t.Fatalf("navigation should end with cookie, got %q", order[len(order)-1])
	}
	if !contains(order, "upgrade-insecure-requests") {
		t.Fatal("navigation order is missing upgrade-insecure-requests")
	}
}

func TestHeaderOrderForDestSubresourceOmitsNavigationHeaders(t *testing.T) {
	order := HeaderOrderForDest("chrome", "script")
	if len(order) == 0 {
		t.Fatal("no order returned for chrome subresources")
	}
	if contains(order, "upgrade-insecure-requests") {
		t.Fatal("subresource order must not carry upgrade-insecure-requests")
	}
	// referer positions differ between navigation and subresource.
	navIdx := indexOf(HeaderOrderForDest("chrome", "document"), "referer")
	subIdx := indexOf(order, "referer")
	if subIdx < 0 {
		t.Fatal("subresource order should include referer")
	}
	if navIdx >= 0 && navIdx == subIdx {
		t.Fatal("subresource referer should not sit where navigation referer sits")
	}
}

func TestHeaderOrderForDestUnknownFallsBackToDocument(t *testing.T) {
	got := HeaderOrderForDest("chrome", "totally-made-up")
	want := HeaderOrderForDest("chrome", "document")
	if len(got) != len(want) {
		t.Fatalf("unknown dest should fall back to document order")
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("fallback order differs at %d", i)
		}
	}
}

func TestHeaderOrderForDestReturnsACopy(t *testing.T) {
	first := HeaderOrderForDest("chrome", "document")
	first[0] = "mutated"

	second := HeaderOrderForDest("chrome", "document")
	if second[0] == "mutated" {
		t.Fatal("HeaderOrderForDest leaked its backing array")
	}
}

func TestHeaderOrderForDestFirefoxHasNoClientHints(t *testing.T) {
	order := HeaderOrderForDest("firefox", "document")
	if contains(order, "sec-ch-ua") {
		t.Fatal("Firefox sends no Client Hints")
	}
	if !contains(order, "te") {
		t.Fatal("Firefox order should include te")
	}
}

func TestApplyHeaderOrderForDestSetsHeaderKey(t *testing.T) {
	hdr := http.Header{}
	ApplyHeaderOrderForDest(hdr, "chrome", "document")

	got := hdr[http.HeaderOrderKey]
	if len(got) == 0 {
		t.Fatal("ApplyHeaderOrderForDest did not set the header order key")
	}
	if got[0] != "sec-ch-ua" {
		t.Fatalf("unexpected first header %q", got[0])
	}
}

func TestHeaderOrderForDestUnknownBrowserIsNoOp(t *testing.T) {
	if order := HeaderOrderForDest("netscape", "document"); order != nil {
		t.Fatal("unknown browser should return nil")
	}
}

func contains(list []string, needle string) bool {
	return indexOf(list, needle) >= 0
}

func indexOf(list []string, needle string) int {
	for i, v := range list {
		if v == needle {
			return i
		}
	}
	return -1
}
