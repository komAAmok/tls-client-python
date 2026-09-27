package main

import (
	"testing"

	http "github.com/bogdanfinn/fhttp"
)

// responseHasNoBody decides whether the engine must read a payload at all.
//
// The regression it guards: a HEAD response advertises the Content-Length of
// the representation the server *would* have sent, but sends no bytes.  Before
// this predicate the engine read that many bytes from the body, blocked until
// the peer closed the connection, and then surfaced
// "failed to read response body: EOF" - so every HEAD request against a
// keep-alive server raised instead of returning the headers.
func TestResponseHasNoBody(t *testing.T) {
	cases := []struct {
		name   string
		method string
		status int
		want   bool
	}{
		{"HEAD with an advertised body", "HEAD", 200, true},
		{"HEAD on a redirect", "HEAD", 302, true},
		{"GET reads its body", "GET", 200, false},
		{"POST reads its body", "POST", 201, false},
		{"204 has no payload", "GET", 204, true},
		{"304 has no payload", "GET", 304, true},
		{"1xx has no payload", "GET", 100, true},
		{"206 still has a payload", "GET", 206, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tc.status,
				Request:    &http.Request{Method: tc.method},
			}
			if got := responseHasNoBody(resp); got != tc.want {
				t.Fatalf("responseHasNoBody(%s, %d) = %v, want %v",
					tc.method, tc.status, got, tc.want)
			}
		})
	}
}

// A nil response, or one without a request, must not panic.
func TestResponseHasNoBodyWithoutRequest(t *testing.T) {
	if responseHasNoBody(nil) {
		t.Fatal("a nil response must not be reported as body-less")
	}
	if responseHasNoBody(&http.Response{StatusCode: 200}) {
		t.Fatal("a response without a request must be read as a body")
	}
}
