// charset_lean.go — decode-only charset sniffing for the response preview.
//
// Why this file exists
// --------------------
// Upstream's debug path calls golang.org/x/net/html/charset.NewReader to
// transcode the logged response body.  That single call links the whole
// x/text/encoding registry through htmlindex, which pulls in every legacy
// codec together with BOTH directions of the CJK conversion tables.  On the
// linux/amd64 shared library that is more than a megabyte — most of the
// binary's encoding weight — for a code path that only runs when debug logging
// is enabled.
//
// The tables that dominate the cost are the *encode* halves
// (traditionalchinese.encode0 alone is >500 KB), while logging only ever
// decodes bytes the server already sent.
//
// How the decode-only property is preserved
// -----------------------------------------
// The link-time saving depends on *how* the codec is referenced, not just on
// which one:
//
//   - A map of `X.NewDecoder` method values keeps the X encoding.Encoding
//     interface itab alive, and that itab carries NewEncoder with it, so the
//     big encode tables stay linked.
//   - A switch whose cases call `X.NewDecoder()` directly lets the compiler
//     devirtualize the call; only the decoder is reachable and the encode
//     tables are dropped entirely.
//
// So this file deliberately uses a switch rather than a lookup table.  Adding
// a codec means adding a case, and the test in charset_lean_test.go pins both
// the decoding behaviour and the recognised label set.
//
// Unknown or UTF-8 labels return the reader unchanged, which is also what
// html/charset does for a label it does not know.

package tls_client

import (
	"io"
	"mime"
	"strings"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/traditionalchinese"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// normalizeCharsetLabel lower-cases a charset label and removes the quotes and
// whitespace a server may wrap it in.
func normalizeCharsetLabel(label string) string {
	label = strings.TrimSpace(strings.ToLower(label))
	label = strings.Trim(label, `"'`)
	return strings.TrimSpace(label)
}

// charsetFromContentType extracts the charset parameter of a Content-Type
// header.  An unparsable header yields an empty label, matching the behaviour
// of a header without a charset.
func charsetFromContentType(contentType string) string {
	if contentType == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return ""
	}
	return normalizeCharsetLabel(params["charset"])
}

// decoderForLabel returns a decoder for a normalised charset label, or nil
// when the label needs no transcoding (UTF-8 and unknown labels).
//
// Every case calls NewDecoder() directly so the call is devirtualized at
// compile time.  Do not rewrite this as a table of method values: that keeps
// the encoding.Encoding itabs (and with them the CJK encode tables) linked.
func decoderForLabel(label string) *encoding.Decoder {
	switch label {
	// Chinese
	case "gb2312", "gbk", "x-gbk", "csgb2312":
		return simplifiedchinese.GBK.NewDecoder()
	case "gb18030":
		return simplifiedchinese.GB18030.NewDecoder()
	case "big5", "big-5", "big5hkscs", "csbig5":
		return traditionalchinese.Big5.NewDecoder()

	// Japanese
	case "shift_jis", "shift-jis", "sjis", "x-sjis", "cp932", "windows-31j", "csshiftjis":
		return japanese.ShiftJIS.NewDecoder()
	case "euc-jp", "eucjp", "cseucpkdfmtjapanese":
		return japanese.EUCJP.NewDecoder()
	case "iso-2022-jp", "csiso2022jp":
		return japanese.ISO2022JP.NewDecoder()

	// Korean
	case "euc-kr", "euckr", "ks_c_5601-1987", "cp949", "cseuckr":
		return korean.EUCKR.NewDecoder()

	// Single-byte and ASCII-compatible
	case "iso-8859-1", "iso8859-1", "latin1", "latin-1", "us-ascii", "ascii", "cp819", "iso-ir-100":
		return charmap.ISO8859_1.NewDecoder()
	case "windows-1252", "cp1252":
		return charmap.Windows1252.NewDecoder()
	case "windows-1251", "cp1251":
		return charmap.Windows1251.NewDecoder()

	// UTF-16 needs the BOM to pick a byte order.
	case "utf-16":
		return unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewDecoder()
	case "utf-16le":
		return unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
	case "utf-16be":
		return unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM).NewDecoder()
	}
	return nil
}

// newCharsetReader wraps r so its bytes are decoded from the charset named in
// the Content-Type header.
//
// It mirrors x/net/html/charset.NewReader for the codecs above: a UTF-8,
// empty or unrecognised label returns the reader unchanged, and a known label
// is transcoded on the fly while the body is read.
func newCharsetReader(r io.Reader, contentType string) (io.Reader, error) {
	label := charsetFromContentType(contentType)
	if label == "" || label == "utf-8" || label == "utf8" {
		return r, nil
	}
	decoder := decoderForLabel(label)
	if decoder == nil {
		return r, nil
	}
	return transform.NewReader(r, decoder), nil
}
