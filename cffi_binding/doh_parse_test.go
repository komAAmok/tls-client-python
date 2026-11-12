package main

import "testing"

// TestParseDoHResponse covers the hand-written DoH JSON decoder that replaced
// encoding/json.  The shapes here are the ones RFC 8484 servers actually emit.
func TestParseDoHResponse(t *testing.T) {
	t.Run("answer with ech", func(t *testing.T) {
		body := []byte(`{"Status":0,"TC":false,"Answer":[{"name":"tls.peet.ws.","type":65,"TTL":300,"data":"AAEABnBlZXQud3M="}]}`)
		got, err := parseDoHResponse(body)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != 0 {
			t.Fatalf("Status = %d, want 0", got.Status)
		}
		if len(got.Answer) != 1 || got.Answer[0].Type != 65 || got.Answer[0].Data != "AAEABnBlZXQud3M=" {
			t.Fatalf("Answer = %+v", got.Answer)
		}
	})

	t.Run("no answer member", func(t *testing.T) {
		// NODATA / NXDOMAIN responses omit "Answer" entirely.
		got, err := parseDoHResponse([]byte(`{"Status":3}`))
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != 3 || len(got.Answer) != 0 {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("status as string", func(t *testing.T) {
		got, err := parseDoHResponse([]byte(`{"Status":"2"}`))
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != 2 {
			t.Fatalf("Status = %d, want 2", got.Status)
		}
	})

	t.Run("unknown members are skipped", func(t *testing.T) {
		body := []byte(`{"Status":0,"Comment":"x \u00e9","AD":true,"Question":[{"name":"a.b.","type":65}],"Answer":[{"type":65,"data":"AA==","extra":{"n":[1,2,{"z":null}]}}]}`)
		got, err := parseDoHResponse(body)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Answer) != 1 || got.Answer[0].Data != "AA==" {
			t.Fatalf("Answer = %+v", got.Answer)
		}
	})

	t.Run("malformed input is an error", func(t *testing.T) {
		for _, body := range []string{``, `{`, `[1,2]`, `{"Status":}`, `{"Status":0} trailing`} {
			if _, err := parseDoHResponse([]byte(body)); err == nil {
				t.Fatalf("parseDoHResponse(%q) returned no error", body)
			}
		}
	})
}
