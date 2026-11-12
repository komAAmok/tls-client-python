package main

// ECH (Encrypted Client Hello) config resolution over DNS HTTPS records
// (RFC 9460), fetched via the DoH JSON API.  Resolving here keeps the
// Python side free of DNS dependencies and lets the result feed
// CustomTlsClient.ech_candidate_payloads.  Mirrors httpcloak's approach:
// per-host TTL cache, self-healing handled by the caller re-resolving
// after an illegal_parameter handshake failure.

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
)

/*
#include <stdlib.h>
*/
import "C"

const (
	dohDefaultEndpoint = "https://cloudflare-dns.com/dns-query"
	dohTimeout         = 5 * time.Second
	echCacheTTL        = time.Hour
	svcParamKeyECH     = 0x0004 // "ech" SvcParamKey (draft-ietf-tls-svcb-ech)
)

// dohEndpoint is configurable via TLS_CLIENT_DOH_ENDPOINT (any DoH server
// speaking the JSON API, e.g. https://dns.alidns.com/resolve for networks
// where cloudflare-dns.com is unreachable).
var dohEndpoint = func() string {
	if v := os.Getenv("TLS_CLIENT_DOH_ENDPOINT"); v != "" {
		return v
	}
	return dohDefaultEndpoint
}()

type echCacheEntry struct {
	data   []byte
	expire time.Time
}

var (
	echCache  sync.Map // host -> echCacheEntry
	echClient = &http.Client{Timeout: dohTimeout}
)

// extractECHFromRDATA parses an HTTPS RR RDATA and returns the raw
// ECHConfigList bytes from the "ech" SvcParam (key 4), or nil.
//
//	RDATA := priority(2) | qname(labels, 0-terminated) | svcparams
//	svcparam := key(2) | length(2) | value
func extractECHFromRDATA(rdata []byte) []byte {
	if len(rdata) < 3 {
		return nil
	}
	pos := 2 // skip SvcPriority

	// Skip the owner/target QNAME: sequence of length-prefixed labels
	// terminated by the zero-length root label.
	for {
		if pos >= len(rdata) {
			return nil
		}
		l := int(rdata[pos])
		pos++
		if l == 0 {
			break
		}
		pos += l
	}

	for pos+4 <= len(rdata) {
		key := int(rdata[pos])<<8 | int(rdata[pos+1])
		vlen := int(rdata[pos+2])<<8 | int(rdata[pos+3])
		pos += 4
		if pos+vlen > len(rdata) {
			return nil
		}
		if key == svcParamKeyECH {
			out := make([]byte, vlen)
			copy(out, rdata[pos:pos+vlen])
			return out
		}
		pos += vlen
	}
	return nil
}

// dohAnswer is one entry of a DoH JSON "Answer" array.  Only the two fields
// the resolver needs are decoded.
type dohAnswer struct {
	Type int
	Data string
}

// dohResponse is the subset of the DoH JSON envelope this resolver reads.
type dohResponse struct {
	Status int
	Answer []dohAnswer
}

// parseDoHResponse decodes the DoH JSON envelope without encoding/json.
//
// The envelope is a flat object whose only interesting members are the numeric
// "Status" and the "Answer" array of {"type":N,"data":"..."} objects.  Pulling
// in encoding/json to read it costs the reflective marshaller, its struct-field
// cache and the entire encoding/json/v2 dependency (plus encoding/base32, cmp
// and the unicode tables) - measured at ~200 KB of .text for a resolver that
// needs none of it.  This scanner accepts the RFC 8484 JSON profile: one flat
// object, a string-or-number status, and an array of flat objects.  It is a
// validator as much as a parser, so a malformed response is an error rather
// than a silently empty result.
func parseDoHResponse(body []byte) (dohResponse, error) {
	var out dohResponse

	p := &jsonScanner{b: body}
	if err := p.expect('{'); err != nil {
		return out, fmt.Errorf("DoH response is not a JSON object: %w", err)
	}

	for {
		p.skipSpace()
		if p.done() {
			return out, fmt.Errorf("DoH response: unterminated object")
		}
		if p.peek() == '}' {
			p.i++
			break
		}

		key, err := p.string()
		if err != nil {
			return out, fmt.Errorf("DoH response key: %w", err)
		}
		if err := p.expect(':'); err != nil {
			return out, err
		}

		switch key {
		case "Status":
			// RFC 8484 says Status is a number; some servers quote it.
			p.skipSpace()
			if !p.done() && p.peek() == '"' {
				raw, err := p.string()
				if err != nil {
					return out, fmt.Errorf("DoH response Status: %w", err)
				}
				n, convErr := strconv.Atoi(raw)
				if convErr != nil {
					return out, fmt.Errorf("DoH response Status is not a number: %q", raw)
				}
				out.Status = n
			} else {
				n, err := p.number()
				if err != nil {
					return out, fmt.Errorf("DoH response Status: %w", err)
				}
				out.Status = int(n)
			}
		case "Answer":
			answers, err := p.answerArray()
			if err != nil {
				return out, fmt.Errorf("DoH response Answer: %w", err)
			}
			out.Answer = answers
		default:
			if err := p.skipValue(); err != nil {
				return out, fmt.Errorf("DoH response field %q: %w", key, err)
			}
		}

		p.skipSpace()
		if p.done() {
			return out, fmt.Errorf("DoH response: unterminated object")
		}
		if p.peek() == ',' {
			p.i++
			continue
		}
		if p.peek() == '}' {
			p.i++
			break
		}
		return out, fmt.Errorf("DoH response: expected ',' or '}' at offset %d", p.i)
	}

	p.skipSpace()
	if !p.done() {
		return out, fmt.Errorf("DoH response: trailing data at offset %d", p.i)
	}
	return out, nil
}

// answerArray decodes the "Answer" member: an array of flat objects with
// numeric "type" and string "data" members.  Unknown members are skipped.
func (p *jsonScanner) answerArray() ([]dohAnswer, error) {
	var out []dohAnswer

	if err := p.expect('['); err != nil {
		return nil, err
	}
	for {
		p.skipSpace()
		if p.done() {
			return nil, fmt.Errorf("unterminated array")
		}
		if p.peek() == ']' {
			p.i++
			return out, nil
		}

		if err := p.expect('{'); err != nil {
			return nil, err
		}
		var answer dohAnswer
		for {
			p.skipSpace()
			if p.done() {
				return nil, fmt.Errorf("unterminated answer object")
			}
			if p.peek() == '}' {
				p.i++
				break
			}
			key, err := p.string()
			if err != nil {
				return nil, err
			}
			if err := p.expect(':'); err != nil {
				return nil, err
			}
			switch key {
			case "type":
				n, err := p.number()
				if err != nil {
					return nil, err
				}
				answer.Type = int(n)
			case "data":
				v, err := p.string()
				if err != nil {
					return nil, err
				}
				answer.Data = v
			default:
				if err := p.skipValue(); err != nil {
					return nil, err
				}
			}
			p.skipSpace()
			if p.done() {
				return nil, fmt.Errorf("unterminated answer object")
			}
			if p.peek() == ',' {
				p.i++
				continue
			}
			if p.peek() == '}' {
				p.i++
				break
			}
			return nil, fmt.Errorf("expected ',' or '}' at offset %d", p.i)
		}
		out = append(out, answer)

		p.skipSpace()
		if p.done() {
			return nil, fmt.Errorf("unterminated array")
		}
		if p.peek() == ',' {
			p.i++
			continue
		}
		if p.peek() == ']' {
			p.i++
			return out, nil
		}
		return nil, fmt.Errorf("expected ',' or ']' at offset %d", p.i)
	}
}

// jsonScanner walks a JSON document byte by byte.
type jsonScanner struct {
	b []byte
	i int
}

func (p *jsonScanner) done() bool { return p.i >= len(p.b) }

func (p *jsonScanner) peek() byte { return p.b[p.i] }

func (p *jsonScanner) skipSpace() {
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *jsonScanner) expect(c byte) error {
	p.skipSpace()
	if p.done() || p.b[p.i] != c {
		return fmt.Errorf("expected %q at offset %d", c, p.i)
	}
	p.i++
	return nil
}

func (p *jsonScanner) string() (string, error) {
	p.skipSpace()
	if err := p.expect('"'); err != nil {
		return "", err
	}
	var b []byte
	for p.i < len(p.b) {
		c := p.b[p.i]
		switch c {
		case '"':
			p.i++
			return string(b), nil
		case '\\':
			p.i++
			if p.done() {
				return "", fmt.Errorf("unterminated escape")
			}
			switch esc := p.b[p.i]; esc {
			case 'n':
				b = append(b, '\n')
			case 't':
				b = append(b, '\t')
			case 'r':
				b = append(b, '\r')
			case 'b':
				b = append(b, '\b')
			case 'f':
				b = append(b, '\f')
			case 'u':
				// \uXXXX: decode to UTF-8.  Surrogate pairs are not needed for
				// base64 payloads, so a lone surrogate becomes U+FFFD in keeping
				// with encoding/json.
				if p.i+4 >= len(p.b) {
					return "", fmt.Errorf("short \\u escape at offset %d", p.i)
				}
				cp32, err := strconv.ParseUint(string(p.b[p.i+1:p.i+5]), 16, 32)
				if err != nil {
					return "", fmt.Errorf("bad \\u escape at offset %d", p.i)
				}
				p.i += 4
				b = appendRune(b, rune(cp32))
			default:
				b = append(b, esc)
			}
			p.i++
		default:
			b = append(b, c)
			p.i++
		}
	}
	return "", fmt.Errorf("unterminated string")
}

func (p *jsonScanner) number() (float64, error) {
	p.skipSpace()
	start := p.i
	for p.i < len(p.b) {
		c := p.b[p.i]
		if (c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E' {
			p.i++
			continue
		}
		break
	}
	if start == p.i {
		return 0, fmt.Errorf("expected a number at offset %d", start)
	}
	return strconv.ParseFloat(string(p.b[start:p.i]), 64)
}

// skipValue validates and discards one JSON value of any shape.
func (p *jsonScanner) skipValue() error {
	p.skipSpace()
	if p.done() {
		return fmt.Errorf("unexpected end of input")
	}
	switch c := p.peek(); {
	case c == '"':
		_, err := p.string()
		return err
	case c == '{':
		p.i++
		for {
			p.skipSpace()
			if p.done() {
				return fmt.Errorf("unterminated object")
			}
			if p.peek() == '}' {
				p.i++
				return nil
			}
			if _, err := p.string(); err != nil {
				return err
			}
			if err := p.expect(':'); err != nil {
				return err
			}
			if err := p.skipValue(); err != nil {
				return err
			}
			p.skipSpace()
			if p.done() {
				return fmt.Errorf("unterminated object")
			}
			if p.peek() == ',' {
				p.i++
				continue
			}
			if p.peek() == '}' {
				p.i++
				return nil
			}
			return fmt.Errorf("expected ',' or '}' at offset %d", p.i)
		}
	case c == '[':
		p.i++
		for {
			p.skipSpace()
			if p.done() {
				return fmt.Errorf("unterminated array")
			}
			if p.peek() == ']' {
				p.i++
				return nil
			}
			if err := p.skipValue(); err != nil {
				return err
			}
			p.skipSpace()
			if p.done() {
				return fmt.Errorf("unterminated array")
			}
			if p.peek() == ',' {
				p.i++
				continue
			}
			if p.peek() == ']' {
				p.i++
				return nil
			}
			return fmt.Errorf("expected ',' or ']' at offset %d", p.i)
		}
	case c == 't' || c == 'f' || c == 'n':
		for p.i < len(p.b) {
			c := p.b[p.i]
			if c >= 'a' && c <= 'z' {
				p.i++
				continue
			}
			break
		}
		return nil
	default:
		_, err := p.number()
		return err
	}
}

// appendRune appends r as UTF-8, mapping surrogates to U+FFFD.
func appendRune(b []byte, r rune) []byte {
	if r >= 0xD800 && r <= 0xDFFF {
		r = 0xFFFD
	}
	return append(b, string(r)...)
}

func fetchECHConfigFromDNS(host string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet,
		dohEndpoint+"?name="+url.QueryEscape(host)+"&type=HTTPS", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/dns-json")

	resp, err := echClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH query status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	parsed, err := parseDoHResponse(body)
	if err != nil {
		return nil, err
	}
	for _, answer := range parsed.Answer {
		if answer.Type != 65 { // HTTPS record
			continue
		}
		rdata, err := base64.StdEncoding.DecodeString(answer.Data)
		if err != nil {
			continue
		}
		if ech := extractECHFromRDATA(rdata); ech != nil {
			return ech, nil
		}
	}
	return nil, nil // no ECH advertised — not an error
}

//export ResolveECHConfig
func ResolveECHConfig(host *C.char) *C.char {
	if host == nil {
		return nil
	}
	name := C.GoString(host)
	if name == "" {
		return nil
	}

	if entry, ok := echCache.Load(name); ok {
		if e := entry.(echCacheEntry); time.Now().Before(e.expire) {
			return C.CString(hex.EncodeToString(e.data))
		}
		echCache.Delete(name)
	}

	payload, err := fetchECHConfigFromDNS(name)
	if err != nil || len(payload) == 0 {
		// Negative results are cached briefly so hot paths don't hammer DoH.
		echCache.Store(name, echCacheEntry{data: nil, expire: time.Now().Add(5 * time.Minute)})
		return nil
	}
	echCache.Store(name, echCacheEntry{data: payload, expire: time.Now().Add(echCacheTTL)})
	return C.CString(hex.EncodeToString(payload))
}
