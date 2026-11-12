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
// Scope of the saving (measured 2026-11-12)
// -----------------------------------------
// The devirtualisation above pays off in a **pure-Go** build: `go build .`
// and the test binaries link 0 bytes of encode tables.  The shipped artifact is
// built with `-buildmode=c-shared`, which forces external linking, and the
// external linker keeps the full encoding.Encoding interface itab — with
// NewEncoder, and therefore the 338 KB of CJK encode tables.  Measured on
// linux/amd64: 26 encode symbols / 338,320 bytes in the .so, against 0 in the
// executable from the same source.
//
// Two things follow.  First, do not "fix" this by rewriting the calls again:
// routing them through a one-method interface was tried in this sync and
// changed nothing in the .so.  Second, the comment above is about the source
// property that is still worth keeping (a pure-Go consumer of this package
// gets the lean link), not about the .so size.  The comment stays because the
// property is real; the number to watch is the budget in
// python_tests/test_binary_size_guard.py, which measures the artifact that
// actually ships.
//
// Fidelity
// --------
// The replacement is a drop-in for html/charset.NewReader: it applies the same
// WHATWG label table (generated from x/text/encoding/htmlindex, the table
// html/charset itself consults), honours the same BOM sniff, runs the same
// <meta> prescan, and falls back to windows-1252 exactly as html/charset does
// when nothing else identifies the encoding.  Pinned by charset_lean_test.go
// against the real html/charset package.
//
// Only the decoder halves are linked.  The <meta> prescan needs x/net/html's
// tokenizer (about 24 KB); the htmlindex table itself is what costs the extra
// ~260 KB, because referencing it pulls in every codec in the registry.

package tls_client

import (
	"bytes"
	"io"
	"mime"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
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
	case "unicode-1-1-utf-8", "unicode11utf8", "unicode20utf8", "utf-8", "utf8", "x-unicode20utf8":
		return unicode.UTF8.NewDecoder()
	case "866", "cp866", "csibm866", "ibm866":
		return charmap.CodePage866.NewDecoder()
	case "csisolatin2", "iso-8859-2", "iso-ir-101", "iso8859-2", "iso88592", "iso_8859-2", "iso_8859-2:1987", "l2", "latin2":
		return charmap.ISO8859_2.NewDecoder()
	case "csisolatin3", "iso-8859-3", "iso-ir-109", "iso8859-3", "iso88593", "iso_8859-3", "iso_8859-3:1988", "l3", "latin3":
		return charmap.ISO8859_3.NewDecoder()
	case "csisolatin4", "iso-8859-4", "iso-ir-110", "iso8859-4", "iso88594", "iso_8859-4", "iso_8859-4:1988", "l4", "latin4":
		return charmap.ISO8859_4.NewDecoder()
	case "csisolatincyrillic", "cyrillic", "iso-8859-5", "iso-ir-144", "iso8859-5", "iso88595", "iso_8859-5", "iso_8859-5:1988":
		return charmap.ISO8859_5.NewDecoder()
	case "arabic", "asmo-708", "csiso88596e", "csiso88596i", "csisolatinarabic", "ecma-114", "iso-8859-6", "iso-8859-6-e", "iso-8859-6-i", "iso-ir-127", "iso8859-6", "iso88596", "iso_8859-6", "iso_8859-6:1987":
		return charmap.ISO8859_6.NewDecoder()
	case "csisolatingreek", "ecma-118", "elot_928", "greek", "greek8", "iso-8859-7", "iso-ir-126", "iso8859-7", "iso88597", "iso_8859-7", "iso_8859-7:1987", "sun_eu_greek":
		return charmap.ISO8859_7.NewDecoder()
	case "csiso88598e", "csisolatinhebrew", "hebrew", "iso-8859-8", "iso-8859-8-e", "iso-ir-138", "iso8859-8", "iso88598", "iso_8859-8", "iso_8859-8:1988", "visual":
		return charmap.ISO8859_8.NewDecoder()
	case "csiso88598i", "iso-8859-8-i", "logical":
		return charmap.ISO8859_8I.NewDecoder()
	case "csisolatin6", "iso-8859-10", "iso-ir-157", "iso8859-10", "iso885910", "l6", "latin6":
		return charmap.ISO8859_10.NewDecoder()
	case "iso-8859-13", "iso8859-13", "iso885913":
		return charmap.ISO8859_13.NewDecoder()
	case "iso-8859-14", "iso8859-14", "iso885914":
		return charmap.ISO8859_14.NewDecoder()
	case "csisolatin9", "iso-8859-15", "iso8859-15", "iso885915", "iso_8859-15", "l9":
		return charmap.ISO8859_15.NewDecoder()
	case "iso-8859-16":
		return charmap.ISO8859_16.NewDecoder()
	case "cskoi8r", "koi", "koi8", "koi8-r", "koi8_r":
		return charmap.KOI8R.NewDecoder()
	case "koi8-ru", "koi8-u":
		return charmap.KOI8U.NewDecoder()
	case "csmacintosh", "mac", "macintosh", "x-mac-roman":
		return charmap.Macintosh.NewDecoder()
	case "dos-874", "iso-8859-11", "iso8859-11", "iso885911", "tis-620", "windows-874":
		return charmap.Windows874.NewDecoder()
	case "cp1250", "windows-1250", "x-cp1250":
		return charmap.Windows1250.NewDecoder()
	case "cp1251", "windows-1251", "x-cp1251":
		return charmap.Windows1251.NewDecoder()
	case "ansi_x3.4-1968", "ascii", "cp1252", "cp819", "csisolatin1", "ibm819", "iso-8859-1", "iso-ir-100", "iso8859-1", "iso88591", "iso_8859-1", "iso_8859-1:1987", "l1", "latin1", "us-ascii", "windows-1252", "x-cp1252":
		return charmap.Windows1252.NewDecoder()
	case "cp1253", "windows-1253", "x-cp1253":
		return charmap.Windows1253.NewDecoder()
	case "cp1254", "csisolatin5", "iso-8859-9", "iso-ir-148", "iso8859-9", "iso88599", "iso_8859-9", "iso_8859-9:1989", "l5", "latin5", "windows-1254", "x-cp1254":
		return charmap.Windows1254.NewDecoder()
	case "cp1255", "windows-1255", "x-cp1255":
		return charmap.Windows1255.NewDecoder()
	case "cp1256", "windows-1256", "x-cp1256":
		return charmap.Windows1256.NewDecoder()
	case "cp1257", "windows-1257", "x-cp1257":
		return charmap.Windows1257.NewDecoder()
	case "cp1258", "windows-1258", "x-cp1258":
		return charmap.Windows1258.NewDecoder()
	case "x-mac-cyrillic", "x-mac-ukrainian":
		return charmap.MacintoshCyrillic.NewDecoder()
	case "chinese", "csgb2312", "csiso58gb231280", "gb2312", "gb_2312", "gb_2312-80", "gbk", "iso-ir-58", "x-gbk":
		return simplifiedchinese.GBK.NewDecoder()
	case "gb18030":
		return simplifiedchinese.GB18030.NewDecoder()
	case "big5", "big5-hkscs", "cn-big5", "csbig5", "x-x-big5":
		return traditionalchinese.Big5.NewDecoder()
	case "cseucpkdfmtjapanese", "euc-jp", "x-euc-jp":
		return japanese.EUCJP.NewDecoder()
	case "csiso2022jp", "iso-2022-jp":
		return japanese.ISO2022JP.NewDecoder()
	case "csshiftjis", "ms932", "ms_kanji", "shift-jis", "shift_jis", "sjis", "windows-31j", "x-sjis":
		return japanese.ShiftJIS.NewDecoder()
	case "cseuckr", "csksc56011987", "euc-kr", "iso-ir-149", "korean", "ks_c_5601-1987", "ks_c_5601-1989", "ksc5601", "ksc_5601", "windows-949":
		return korean.EUCKR.NewDecoder()
	case "csiso2022kr", "hz-gb-2312", "iso-2022-cn", "iso-2022-cn-ext", "iso-2022-kr", "replacement":
		return encoding.Replacement.NewDecoder()
	case "unicodefffe", "utf-16be":
		return unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM).NewDecoder()
	case "csunicode", "iso-10646-ucs-2", "ucs-2", "unicode", "unicodefeff", "utf-16", "utf-16le":
		return unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
	case "x-user-defined":
		return charmap.XUserDefined.NewDecoder()
	}
	return nil
}

// boms is html/charset's byte-order-mark table, in its precedence order.
var boms = []struct {
	bom []byte
	enc string
}{
	{[]byte{0xfe, 0xff}, "utf-16be"},
	{[]byte{0xff, 0xfe}, "utf-16le"},
	{[]byte{0xef, 0xbb, 0xbf}, "utf-8"},
}

// prescan mirrors html/charset's <meta> sniff: it looks for a
// <meta charset=...> or <meta http-equiv="Content-Type" content="..."> in the
// first 1024 bytes and returns the label it names.
//
// It uses x/net/html's tokenizer, the same one html/charset uses, so the parse
// matches.  That tokenizer costs about 24 KB; the htmlindex table that would
// pull in the encode halves is what is avoided.
func prescan(content []byte) string {
	z := html.NewTokenizer(bytes.NewReader(content))
	for {
		switch z.Next() {
		case html.ErrorToken:
			return ""

		case html.StartTagToken, html.SelfClosingTagToken:
			tagName, hasAttr := z.TagName()
			if !bytes.Equal(tagName, []byte("meta")) {
				continue
			}
			attrList := make(map[string]bool)
			gotPragma := false

			const (
				dontKnow = iota
				doNeedPragma
				doNotNeedPragma
			)
			needPragma := dontKnow

			name := ""
			found := false
			for hasAttr {
				var key, val []byte
				key, val, hasAttr = z.TagAttr()
				ks := string(key)
				if attrList[ks] {
					continue
				}
				attrList[ks] = true
				for i, c := range val {
					if 'A' <= c && c <= 'Z' {
						val[i] = c + 0x20
					}
				}

				switch ks {
				case "http-equiv":
					if bytes.Equal(val, []byte("content-type")) {
						gotPragma = true
					}

				case "content":
					if !found {
						if l := fromMetaElement(string(val)); l != "" {
							name, found = l, true
							needPragma = doNeedPragma
						}
					}

				case "charset":
					name, found = string(val), true
					needPragma = doNotNeedPragma
				}
			}

			if needPragma == dontKnow || needPragma == doNeedPragma && !gotPragma {
				continue
			}

			// A <meta> naming a UTF-16 encoding is treated as UTF-8, per
			// the HTML spec and html/charset.  html/charset assigns
			// encoding.Nop here, so the body is not re-decoded.
			if strings.HasPrefix(name, "utf-16") {
				return noTranscode
			}
			if decoderForLabel(normalizeCharsetLabel(name)) != nil {
				return name
			}
		}
	}
}

// fromMetaElement extracts the charset from a Content-Type-style meta value.
func fromMetaElement(s string) string {
	for s != "" {
		csLoc := strings.Index(s, "charset")
		if csLoc == -1 {
			return ""
		}
		s = s[csLoc+len("charset"):]
		s = strings.TrimLeft(s, " \t\n\f\r")
		if !strings.HasPrefix(s, "=") {
			continue
		}
		s = s[1:]
		s = strings.TrimLeft(s, " \t\n\f\r")
		if s == "" {
			return ""
		}
		if q := s[0]; q == '"' || q == '\'' {
			s = s[1:]
			closeQuote := strings.IndexRune(s, rune(q))
			if closeQuote == -1 {
				return ""
			}
			return s[:closeQuote]
		}

		end := strings.IndexAny(s, "; \t\n\f\r")
		if end == -1 {
			end = len(s)
		}
		return s[:end]
	}
	return ""
}

// noTranscode is returned by detectLabel when html/charset would resolve the
// encoding to encoding.Nop, which NewReader treats as "return the reader
// unchanged" rather than "wrap it in a UTF-8 decoder".  The two are not the
// same: a UTF-8 decoder rewrites invalid byte sequences to U+FFFD, while Nop
// passes them through untouched.
const noTranscode = "\x00nop"

// detectLabel mirrors html/charset.DetermineEncoding: a BOM wins, then the
// Content-Type charset parameter, then a <meta> prescan, then a UTF-8 validity
// check, and finally the windows-1252 default.
//
// It returns noTranscode where DetermineEncoding returns encoding.Nop.
func detectLabel(content []byte, contentType string) string {
	if len(content) > 1024 {
		content = content[:1024]
	}

	for _, b := range boms {
		if bytes.HasPrefix(content, b.bom) {
			return b.enc
		}
	}

	if label := charsetFromContentType(contentType); label != "" {
		if decoderForLabel(label) != nil {
			return label
		}
	}

	if len(content) > 0 {
		if label := prescan(content); label != "" {
			return normalizeCharsetLabel(label)
		}
	}

	// Try to detect UTF-8.  First eliminate any partial rune at the end.
	for i := len(content) - 1; i >= 0 && i > len(content)-4; i-- {
		b := content[i]
		if b < 0x80 {
			break
		}
		if utf8.RuneStart(b) {
			content = content[:i]
			break
		}
	}
	for _, c := range content {
		if c >= 0x80 {
			if utf8.Valid(content) {
				return noTranscode
			}
			break
		}
	}

	return "windows-1252"
}

// isTextualContentType reports whether a Content-Type names a payload whose
// bytes are characters, and therefore whether a charset transcode is
// meaningful at all.
//
// html/charset is only ever reached for HTML documents in its intended use,
// but the debug body-preview in client.go runs it over *every* response.  For
// a binary payload the "windows-1252 default" that DetermineEncoding falls back
// to is actively destructive: every byte in 0x80-0x9F becomes a printable
// character, so an image or archive comes back longer than the server sent it
// and no longer decodes.  A text/*, +json or +xml type (or a missing
// Content-Type, where the preview is being logged as text) keeps the old
// behaviour.
func isTextualContentType(contentType string) bool {
	if strings.TrimSpace(contentType) == "" {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		// An unparsable header is treated as text: that is what the
		// html/charset fallback did, and it keeps the preview readable.
		return true
	}
	mediaType = strings.ToLower(mediaType)
	if strings.HasPrefix(mediaType, "text/") {
		return true
	}
	switch mediaType {
	case "application/json", "application/xml", "application/javascript",
		"application/x-www-form-urlencoded", "application/ecmascript":
		return true
	}
	return strings.HasSuffix(mediaType, "+json") ||
		strings.HasSuffix(mediaType, "+xml") ||
		strings.HasSuffix(mediaType, "+text")
}

// newCharsetReader wraps r so its bytes are decoded from the charset the
// response declares.
//
// It is a drop-in replacement for x/net/html/charset.NewReader: it reads a
// 1024-byte preview, resolves the encoding exactly as html/charset does
// (BOM, then Content-Type, then <meta> prescan, then UTF-8 detection, then the
// windows-1252 default) and transcodes the body on the fly when the resolved
// encoding is not a no-op.
//
// A non-textual Content-Type is returned untouched.  The transcode is a
// no-op for valid UTF-8, but the windows-1252 fallback rewrites every byte in
// 0x80-0x9F, which corrupts binary payloads.
func newCharsetReader(r io.Reader, contentType string) (io.Reader, error) {
	if !isTextualContentType(contentType) {
		return r, nil
	}

	preview := make([]byte, 1024)
	n, err := io.ReadFull(r, preview)
	switch {
	case err == io.ErrUnexpectedEOF:
		preview = preview[:n]
		r = bytes.NewReader(preview)
	case err != nil:
		return nil, err
	default:
		r = io.MultiReader(bytes.NewReader(preview), r)
	}

	label := detectLabel(preview, contentType)
	if label == noTranscode {
		return r, nil
	}
	decoder := decoderForLabel(label)
	if decoder == nil {
		return r, nil
	}
	return transform.NewReader(r, decoder), nil
}

// decodeBodyForLog returns the bytes to show in the debug body preview.
//
// The response itself is never rewritten (see the LOCAL OVERLAY note in
// client.go); this produces a separate, decoded view for the log line only.
// A non-textual Content-Type is returned unchanged so the log does not fill
// with replacement characters, and a decode error falls back to the raw bytes
// rather than losing the preview.
func decodeBodyForLog(body []byte, contentType string) []byte {
	if len(body) == 0 || !isTextualContentType(contentType) {
		return body
	}
	r, err := newCharsetReader(bytes.NewReader(body), contentType)
	if err != nil {
		return body
	}
	decoded, err := io.ReadAll(r)
	if err != nil {
		return body
	}
	return decoded
}
