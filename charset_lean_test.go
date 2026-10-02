package tls_client

import (
	"io"
	"strings"
	"testing"
)

// The debug body preview decodes the response bytes before logging them.  The
// charset_lean.go replacement exists to keep the x/text encode tables out of
// the shared library, so these tests pin the behaviour that must survive it.

// decodePreview runs a body through newCharsetReader and returns the result.
func decodePreview(t *testing.T, body string, contentType string) string {
	t.Helper()
	r, err := newCharsetReader(strings.NewReader(body), contentType)
	if err != nil {
		t.Fatalf("newCharsetReader(%q) returned %v", contentType, err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading decoded body failed: %v", err)
	}
	return string(out)
}

func TestNewCharsetReaderDecodesKnownLabels(t *testing.T) {
	// Byte sequences for CJK text in each family's own encoding.
	cases := []struct {
		label    string
		body     []byte
		expected string
	}{
		{"gbk", []byte{0xD6, 0xD0, 0xCE, 0xC4}, "中文"},
		{"GB2312", []byte{0xD6, 0xD0, 0xCE, 0xC4}, "中文"},
		{"gb18030", []byte{0xD6, 0xD0, 0xCE, 0xC4}, "中文"},
		{"big5", []byte{0xA4, 0xA4, 0xA4, 0xE5}, "中文"},
		{"shift_jis", []byte{0x93, 0xFA, 0x96, 0x7B}, "日本"},
		{"euc-jp", []byte{0xC6, 0xFC, 0xCB, 0xDC}, "日本"},
		{"euc-kr", []byte{0xC7, 0xD1, 0xB1, 0xB9}, "한국"},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			got := decodePreview(t, string(tc.body), "text/html; charset="+tc.label)
			if got != tc.expected {
				t.Fatalf("charset %s decoded to %q, want %q", tc.label, got, tc.expected)
			}
		})
	}
}

func TestNewCharsetReaderLeavesUTF8AndUnknownAlone(t *testing.T) {
	const body = "café ✓ 中文"
	for _, label := range []string{"", "utf-8", "UTF-8", "utf8", "no-such-charset", "x-user-defined"} {
		t.Run(label, func(t *testing.T) {
			contentType := "application/json"
			if label != "" {
				contentType += "; charset=" + label
			}
			if got := decodePreview(t, body, contentType); got != body {
				t.Fatalf("label %q changed the body: %q", label, got)
			}
		})
	}
}

func TestNewCharsetReaderHandlesOddContentTypes(t *testing.T) {
	const body = "plain"
	for _, contentType := range []string{
		"",
		"text/plain",
		"text/plain;",
		"not a media type",
		"text/plain; charset",
		"text/plain; charset=",
		`text/html; charset="gbk"`, // quoted label, no bytes to transcode
	} {
		t.Run(contentType, func(t *testing.T) {
			if got := decodePreview(t, body, contentType); got != body {
				t.Fatalf("content type %q changed the body: %q", contentType, got)
			}
		})
	}
}

func TestNewCharsetReaderIsCaseAndQuoteInsensitive(t *testing.T) {
	body := string([]byte{0xD6, 0xD0, 0xCE, 0xC4})
	for _, label := range []string{"GBK", "  gbk  ", `"GBK"`, "'gbk'"} {
		t.Run(label, func(t *testing.T) {
			got := decodePreview(t, body, "text/html; charset="+label)
			if got != "中文" {
				t.Fatalf("label %q decoded to %q, want 中文", label, got)
			}
		})
	}
}

func TestCharsetFromContentType(t *testing.T) {
	cases := map[string]string{
		"":                                  "",
		"text/html":                         "",
		"text/html; charset=UTF-8":          "utf-8",
		"text/html; charset=gbk":            "gbk",
		`text/html; charset="big5"`:         "big5",
		"text/html; charset=shift_jis; x=1": "shift_jis",
	}
	for contentType, want := range cases {
		t.Run(contentType, func(t *testing.T) {
			if got := charsetFromContentType(contentType); got != want {
				t.Fatalf("charsetFromContentType(%q) = %q, want %q", contentType, got, want)
			}
		})
	}
}

// TestDecoderForLabelIsDecodeOnly documents the invariant the linker relies on:
// every label in the switch must resolve, and unknown labels must not.
func TestDecoderForLabelIsDecodeOnly(t *testing.T) {
	for _, label := range []string{
		"gbk", "gb2312", "gb18030", "big5", "shift_jis", "euc-jp",
		"iso-2022-jp", "euc-kr", "iso-8859-1", "windows-1252", "utf-16",
	} {
		if decoderForLabel(label) == nil {
			t.Errorf("decoderForLabel(%q) = nil, want a decoder", label)
		}
	}
	for _, label := range []string{"utf-8", "utf8", "", "nope"} {
		if decoderForLabel(label) != nil {
			t.Errorf("decoderForLabel(%q) returned a decoder, want nil", label)
		}
	}
}
