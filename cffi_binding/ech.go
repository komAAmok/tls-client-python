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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
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
	echCache   sync.Map // host -> echCacheEntry
	echClient  = &http.Client{Timeout: dohTimeout}
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

type dohAnswer struct {
	Type int    `json:"type"`
	Data string `json:"data"`
}

type dohResponse struct {
	Status int         `json:"Status"`
	Answer []dohAnswer `json:"Answer"`
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

	var parsed dohResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
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
