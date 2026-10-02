package tls_client

import (
	"io"
	"strings"
	"testing"

	"golang.org/x/net/html/charset"
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
	// Valid UTF-8 bytes survive: a recognised UTF-8 label decodes to the same
	// text, an unknown label is ignored, and no label leaves the (valid) body
	// untouched because DetermineEncoding detects UTF-8.
	const body = "café ✓ 中文"
	for _, label := range []string{"", "utf-8", "UTF-8", "utf8", "no-such-charset"} {
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

// TestNewCharsetReaderReplacesInvalidUTF8 pins the distinction between a real
// UTF-8 decoder and encoding.Nop.  html/charset wraps the body when the label
// explicitly names UTF-8 (so invalid bytes become U+FFFD) but leaves it alone
// when UTF-8 was merely *detected* from the bytes.
func TestNewCharsetReaderReplacesInvalidUTF8(t *testing.T) {
	bad := string([]byte{0x41, 0xFF, 0x42})

	if got := decodePreview(t, bad, "text/html; charset=utf-8"); got != "A\uFFFDB" {
		t.Errorf("explicit utf-8 label gave %q, want A\uFFFDB", got)
	}
	if got := decodePreview(t, bad, "text/html"); got != "A\u00FFB" {
		t.Errorf("undetected label gave %q, want the windows-1252 default A\u00FFB", got)
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
// every label in the switch must resolve, and labels htmlindex does not know
// must not.  It is the htmlindex table that is mirrored, so a label the
// standard table lacks (latin-1, cp932, eucjp, cp949, big-5, big5hkscs) stays
// unknown here too -- html/charset ignores those as well.
func TestDecoderForLabelIsDecodeOnly(t *testing.T) {
	for _, label := range []string{
		"gbk", "gb2312", "gb18030", "big5", "shift_jis", "euc-jp",
		"iso-2022-jp", "euc-kr", "iso-8859-1", "windows-1252", "utf-16",
		"utf-8", "utf8", "x-user-defined", "replacement", "koi8-r",
	} {
		if decoderForLabel(label) == nil {
			t.Errorf("decoderForLabel(%q) = nil, want a decoder", label)
		}
	}
	for _, label := range []string{
		"", "nope", "latin-1", "big-5", "big5hkscs", "cp932", "eucjp", "cp949",
	} {
		if decoderForLabel(label) != nil {
			t.Errorf("decoderForLabel(%q) returned a decoder, want nil", label)
		}
	}
}

// TestCharsetLeanMatchesUpstream is the guard that keeps the replacement
// honest.  charset_lean.go exists only to avoid linking the encode halves of
// the x/text codecs; it must not change what a response body decodes to.  This
// test imports the real html/charset (test-only, so the shipped library never
// links it) and asserts the two agree byte-for-byte across the label table and
// every detection path: BOM, Content-Type, <meta> prescan, UTF-8 detection and
// the windows-1252 fallback.
func TestCharsetLeanMatchesUpstream(t *testing.T) {
	bodies := [][]byte{
		{0x93, 0x94, 0x85, 0x91},       // cp1252 punctuation range
		{0xD6, 0xD0, 0xCE, 0xC4},       // GBK 中文
		{0xA4, 0xA4, 0xA4, 0xE5},       // Big5 中文
		{0x93, 0xFA, 0x96, 0x7B},       // Shift_JIS 日本
		{0xC6, 0xFC, 0xCB, 0xDC},       // EUC-JP 日本
		{0xC7, 0xD1, 0xB1, 0xB9},       // EUC-KR 한국
		{0x41, 0x42, 0x43},             // pure ASCII
		[]byte("café ✓ 中文"),            // valid UTF-8 with high bytes
		{0x41, 0xFF, 0x42},             // invalid UTF-8, high bit set
		{0xFF, 0xFE, 0x68, 0x00},       // UTF-16LE BOM
		{0xFE, 0xFF, 0x00, 0x68},       // UTF-16BE BOM
		{0xEF, 0xBB, 0xBF, 0x68, 0x69}, // UTF-8 BOM
		{},                             // empty body
	}
	// Every label htmlindex knows, plus the ones it does not (which upstream
	// ignores) and the sentinels the detection paths need.
	labels := []string{
		"", "utf-8", "utf8", "UTF-8", "no-such-charset",
		"latin-1", "big-5", "big5hkscs", "cp932", "eucjp", "cp949",
		"iso-8859-1", "latin1", "us-ascii", "ascii", "cp819", "iso-ir-100",
		"windows-1252", "windows-1251", "gbk", "gb2312", "gb18030",
		"big5", "shift_jis", "shift-jis", "sjis", "windows-31j",
		"euc-jp", "iso-2022-jp", "euc-kr", "koi8-r", "ibm866",
		"x-user-defined", "replacement", "hz-gb-2312", "utf-16", "utf-16le", "utf-16be",
	}
	// <meta> prescan paths.
	metaBodies := [][]byte{
		append([]byte(`<meta charset="gbk">`), 0xD6, 0xD0, 0xCE, 0xC4),
		append([]byte(`<meta http-equiv="Content-Type" content="text/html; charset=gbk">`), 0xD6, 0xD0, 0xCE, 0xC4),
		append([]byte(`<meta content="text/html; charset=gbk">`), 0xD6, 0xD0, 0xCE, 0xC4),
		append([]byte(`<meta charset="utf-16">`), 'h', 'i'),
	}

	compare := func(t *testing.T, body []byte, contentType string) {
		t.Helper()
		up, upErr := charset.NewReader(strings.NewReader(string(body)), contentType)
		var upOut []byte
		if upErr == nil {
			upOut, _ = io.ReadAll(up)
		}
		lean, leanErr := newCharsetReader(strings.NewReader(string(body)), contentType)
		var leanOut []byte
		if leanErr == nil {
			leanOut, _ = io.ReadAll(lean)
		}
		if string(upOut) != string(leanOut) || (upErr == nil) != (leanErr == nil) {
			t.Errorf("content type %q body %x: html/charset gave %q (err %v), "+
				"charset_lean gave %q (err %v)",
				contentType, body, string(upOut), upErr, string(leanOut), leanErr)
		}
	}

	for _, label := range labels {
		for _, body := range bodies {
			contentType := "text/html"
			if label != "" {
				contentType += "; charset=" + label
			}
			compare(t, body, contentType)
		}
	}
	for _, body := range metaBodies {
		compare(t, body, "text/html")
	}
}

// TestNewCharsetReaderLeavesBinaryBodiesAlone pins the data-integrity guard.
//
// The debug body-preview runs newCharsetReader over every response, not just
// HTML.  For a binary payload the windows-1252 fallback rewrites every byte in
// 0x80-0x9F into a printable character, so an image came back longer than the
// server sent it and no longer decoded.  A non-textual Content-Type must be
// passed through byte-for-byte.
func TestNewCharsetReaderLeavesBinaryBodiesAlone(t *testing.T) {
	binary := make([]byte, 256)
	for i := range binary {
		binary[i] = byte(i)
	}
	for _, contentType := range []string{
		"image/png",
		"image/jpeg",
		"application/octet-stream",
		"application/zip",
		"application/pdf",
		"application/gzip",
		"video/mp4",
		"font/woff2",
		"application/vnd.ms-excel",
	} {
		t.Run(contentType, func(t *testing.T) {
			got := decodePreview(t, string(binary), contentType)
			if got != string(binary) {
				t.Fatalf("content type %q altered a binary body (%d bytes in, %d out)",
					contentType, len(binary), len(got))
			}
		})
	}
}

// TestNewCharsetReaderStillDecodesTextualTypes is the other half: the guard
// must not disable transcoding for the payloads it exists to serve.
func TestNewCharsetReaderStillDecodesTextualTypes(t *testing.T) {
	gbk := string([]byte{0xD6, 0xD0, 0xCE, 0xC4}) // 中文
	for _, contentType := range []string{
		"text/html; charset=gbk",
		"text/plain; charset=gbk",
		"application/json; charset=gbk",
		"application/xml; charset=gbk",
		"application/ld+json; charset=gbk",
		"image/svg+xml; charset=gbk",
	} {
		t.Run(contentType, func(t *testing.T) {
			if got := decodePreview(t, gbk, contentType); got != "中文" {
				t.Fatalf("content type %q decoded to %q, want 中文", contentType, got)
			}
		})
	}
}

func TestIsTextualContentType(t *testing.T) {
	textual := []string{
		"", "text/html", "text/plain; charset=utf-8", "application/json",
		"application/xml", "application/ld+json", "image/svg+xml",
		"application/javascript", "not a media type",
	}
	for _, ct := range textual {
		if !isTextualContentType(ct) {
			t.Errorf("isTextualContentType(%q) = false, want true", ct)
		}
	}
	binary := []string{
		"image/png", "image/jpeg", "application/octet-stream",
		"application/zip", "application/pdf", "video/mp4", "font/woff2",
	}
	for _, ct := range binary {
		if isTextualContentType(ct) {
			t.Errorf("isTextualContentType(%q) = true, want false", ct)
		}
	}
}
