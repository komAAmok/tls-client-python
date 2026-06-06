package main

/*
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    const char* key;
    const char* value;
} HttpHeader;

typedef struct {
    const char* host;
    const char** pins;
    int   pins_len;
} PinEntry;

typedef struct {
    unsigned int streamDep;
    int          exclusive;
    unsigned char weight;
} PriorityParam;

typedef struct {
    PriorityParam priorityParam;
    unsigned int  streamID;
} PriorityFrame;

typedef struct {
    const char* kdfId;
    const char* aeadId;
} CandidateCipherSuite;

typedef struct {
    const char* cert_pem;
    int   cert_pem_len;
    const char* key_pem;
    int   key_pem_len;
} ClientCertificate;

typedef struct {
    const char** h2_settings_keys;
    unsigned int* h2_settings_values;
    int   h2_settings_len;
    const char** h2_settings_order;
    int   h2_settings_order_len;
    const char** h3_settings_keys;
    unsigned long long* h3_settings_values;
    int   h3_settings_len;
    const char** h3_settings_order;
    int   h3_settings_order_len;
    const char** h3_pseudo_header_order;
    int   h3_pseudo_header_order_len;
    PriorityParam* header_priority;
    const char** cert_compression_algos;
    int   cert_compression_algos_len;
    const char* ja3_string;
    const char** key_share_curves;
    int   key_share_curves_len;
    const char** alpn_protocols;
    int   alpn_protocols_len;
    const char** alps_protocols;
    int   alps_protocols_len;
    unsigned short* ech_candidate_payloads;
    int   ech_candidate_payloads_len;
    CandidateCipherSuite* ech_candidate_cipher_suites;
    int   ech_candidate_cipher_suites_len;
    PriorityFrame* priority_frames;
    int   priority_frames_len;
    const char** pseudo_header_order;
    int   pseudo_header_order_len;
    const char** supported_delegated_credentials_algorithms;
    int   supported_delegated_credentials_algorithms_len;
    const char** supported_signature_algorithms;
    int   supported_signature_algorithms_len;
    const char** supported_versions;
    int   supported_versions_len;
    unsigned int   connection_flow;
    unsigned short record_size_limit;
    unsigned int   stream_id;
    unsigned int   h3_priority_param;
    int   h3_send_grease_frames;
    int   allow_http;
} CustomTlsClient;

typedef struct {
    const char* method;
    const char* url;
    const char* body;
    int   body_len;
    const char* proxy;
    const char* client_identifier;
    HttpHeader* headers;
    int   headers_len;
    const char** header_order;
    int   header_order_len;
    const char** pseudo_header_order;
    int   pseudo_header_order_len;
    const char** h3_pseudo_header_order;
    int   h3_pseudo_header_order_len;
    int   timeout_seconds;
    int   timeout_milliseconds;
    int   follow_redirects;
    int   insecure_skip_verify;
    int   force_http1;
    int   with_random_tls_extension_order;
    int   with_protocol_racing;
    const char* server_name_overwrite;
    const char* request_host_override;
    const char* local_address;
    int   max_idle_connections;
    int   max_idle_connections_per_host;
    int   max_connections_per_host;
    int   max_response_header_bytes;
    int   write_buffer_size;
    int   read_buffer_size;
    int   idle_conn_timeout_seconds;
    int   disable_keep_alives;
    int   disable_compression;
    int   allow_empty_cookies;
    int   disable_http3;
    int   disable_ipv4;
    int   disable_ipv6;
    int   without_cookie_jar;
    int   catch_panics;
    int   with_debug;
    const char* stream_output_path;
    int   stream_output_block_size;
    const char* stream_output_eof_symbol;
    HttpHeader* default_headers;
    int   default_headers_len;
    HttpHeader* connect_headers;
    int   connect_headers_len;
    PinEntry* certificate_pinning_hosts;
    int   certificate_pinning_hosts_len;
    int   with_default_bad_pin_handler;
    HttpHeader* request_cookies;
    int   request_cookies_len;
    ClientCertificate* client_certificates;
    int   client_certificates_len;
    CustomTlsClient* custom_tls_client;
    const char* cache_key_hash;
} RequestOptions;

typedef struct {
    int   status_code;
    char* body;
    int   body_len;
    char* err_msg;
    char* target_url;
    char* used_protocol;
    HttpHeader* response_headers;
    int   response_headers_len;
    HttpHeader* cookies;
    int   cookies_len;
    char* _resp_strings;
} ResponseResult;

typedef struct {
    long long total_evictions;       // cumulative entries evicted since process start
    long long last_eviction_count;   // entries evicted in the most recent scan
    long long last_eviction_time;    // UnixNano timestamp of the last eviction scan
    long long pool_entry_count;      // current number of entries in the client pool
    long long pool_ttl_seconds;      // current TTL (seconds)
    long long pool_scan_interval_seconds; // current scan interval (seconds)
} PoolStats;

typedef void (*async_callback_fn)(uintptr_t request_id, ResponseResult* response);

// C helper: invoke the callback from Go.
// cgo cannot call C function pointers directly (they appear as opaque [0]byte),
// so we wrap the call in a static inline C function that takes a void*.
static inline void invoke_async_callback(void* fn, uintptr_t request_id, ResponseResult* response) {
	if (fn != NULL) {
		((async_callback_fn)fn)(request_id, response);
	}
}
*/
import "C"

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	http "github.com/bogdanfinn/fhttp"
	http2 "github.com/bogdanfinn/fhttp/http2"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

// ---------------------------------------------------------------------------
// Client pool – caches HttpClients keyed by the configuration parameters that
// affect the TLS handshake and connection pool behaviour.
//
// Each HttpClient is wrapped in a poolEntry that tracks the last access time.
// A background goroutine scans the pool at regular intervals and evicts
// entries whose lastAccess is older than poolTTL.  This prevents unbounded
// RSS growth under high-throughput workloads that use many distinct
// configurations (e.g. rotating proxies).
// ---------------------------------------------------------------------------

type poolEntry struct {
	client     tls_client.HttpClient
	lastAccess atomic.Int64 // UnixNano timestamp of last retrieval
}

var (
	clientPool        sync.Map
	clientPoolMu      sync.Mutex
	poolTTLNs         atomic.Int64 // pool entry idle timeout (nanoseconds); default 5 min
	poolScanIntervalNs atomic.Int64 // eviction scan interval (nanoseconds); default 60 s
	evictionStopCh    chan struct{}
	evictionOnce      sync.Once

	// Eviction metrics — updated atomically by the eviction goroutine.
	totalEvictions    atomic.Int64 // cumulative entries evicted since process start
	lastEvictionCount atomic.Int64 // entries evicted in the most recent scan
	lastEvictionTime  atomic.Int64 // UnixNano timestamp of the most recent scan
)

func init() {
	poolTTLNs.Store(int64(5 * time.Minute))
	poolScanIntervalNs.Store(int64(60 * time.Second))
}

// startEviction launches the background TTL eviction goroutine (idempotent).
// Uses time.Sleep in a loop (not a ticker) so SetPoolScanInterval changes
// take effect on the next sleep cycle without restarting the goroutine.
func startEviction() {
	evictionOnce.Do(func() {
		evictionStopCh = make(chan struct{})
		go func() {
			interval := time.Duration(poolScanIntervalNs.Load())
			if interval <= 0 {
				interval = 60 * time.Second
			}
			timer := time.NewTimer(interval)
			defer timer.Stop()
			for {
				select {
				case <-timer.C:
					evictStaleEntries()
					interval = time.Duration(poolScanIntervalNs.Load())
					if interval <= 0 {
						interval = 60 * time.Second
					}
					timer.Reset(interval)
				case <-evictionStopCh:
					return
				}
			}
		}()
	})
}

// evictStaleEntries scans the pool and removes entries whose lastAccess
// is older than poolTTL, calling CloseIdleConnections on each removed client.
func evictStaleEntries() {
	ttl := time.Duration(poolTTLNs.Load())
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	cutoff := time.Now().Add(-ttl).UnixNano()

	var toDelete []any
	clientPool.Range(func(key, value any) bool {
		entry, ok := value.(*poolEntry)
		if !ok {
			// Orphaned/bad entry — clean up
			toDelete = append(toDelete, key)
			return true
		}
		if entry.lastAccess.Load() < cutoff {
			toDelete = append(toDelete, key)
		}
		return true
	})

	var evicted int64
	// Serialise with ClearClientPool and getOrCreateClient construction.
	// Cache-hit lastAccess updates happen without this lock (atomic.Int64),
	// but the re-check below catches concurrent refreshes regardless.
	clientPoolMu.Lock()
	defer clientPoolMu.Unlock()

	for _, key := range toDelete {
		entry, ok := clientPool.Load(key)
		if !ok {
			continue // already removed by another goroutine
		}
		pe, ok := entry.(*poolEntry)
		if !ok {
			// Orphaned / type-mismatched entry — remove unconditionally.
			clientPool.Delete(key)
			evicted++
			continue
		}
		// Re-check lastAccess under the lock: a concurrent request may have
		// refreshed the entry since the Range scan completed.
		if pe.lastAccess.Load() >= cutoff {
			continue
		}
		if pe.client != nil {
			pe.client.CloseIdleConnections()
		}
		clientPool.Delete(key)
		evicted++
	}

	// Update metrics atomically so GetPoolStats can read them lock-free.
	if evicted > 0 {
		totalEvictions.Add(evicted)
	}
	lastEvictionCount.Store(evicted)
	lastEvictionTime.Store(time.Now().UnixNano())
}

// respBodyPool reuses *bytes.Buffer for response body reads, avoiding
// the repeated internal buffer expansions of io.ReadAll that generate
// GC pressure under high-throughput synchronous workloads.
var respBodyPool = sync.Pool{
	New: func() any {
		return bytes.NewBuffer(make([]byte, 0, 65536))
	},
}

// readAllPooled is a sync.Pool-backed replacement for io.ReadAll.
// The returned slice is a copy — the caller owns it and the pool buffer
// is immediately returned for reuse.
func readAllPooled(r io.Reader) ([]byte, error) {
	buf := respBodyPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		respBodyPool.Put(buf)
	}()
	if _, err := buf.ReadFrom(r); err != nil {
		return nil, err
	}
	// Copy out of the pooled buffer so the pool can safely reuse the
	// backing array on the next Get.
	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	return out, nil
}

// readBodyToCHeap reads the response body directly into C heap memory
// when Content-Length is positive and within a reasonable bound.
// Returns (body, length, nil) on success, (nil, 0, nil) to signal
// that the caller should fall back to readAllPooled, or (nil, 0, err)
// on read error (C memory already freed).
func readBodyToCHeap(body io.Reader, contentLength int64) (*C.char, int, error) {
	// 128 MB sanity cap — larger than any reasonable TLS-fingerprinting
	// response and well within address-space limits.
	if contentLength <= 0 || contentLength > 128*1024*1024 {
		return nil, 0, nil
	}
	cBody := C.malloc(C.size_t(contentLength))
	if cBody == nil {
		return nil, 0, nil
	}
	cSlice := unsafe.Slice((*byte)(cBody), contentLength)
	if _, err := io.ReadFull(body, cSlice); err != nil {
		C.free(cBody)
		return nil, 0, err
	}
	return (*C.char)(cBody), int(contentLength), nil
}

// ---------------------------------------------------------------------------
// Go-native request config — goroutine-safe copy of all C RequestOptions data.
// Deep-copied by RequestAsync so the goroutine never touches C memory owned by
// Python (which may be freed immediately after RequestAsync returns).
// ---------------------------------------------------------------------------

type requestConfig struct {
	method                   string
	url                      string
	body                     []byte
	proxy                    string
	clientIdentifier         string
	headers                  http.Header
	headerOrder              []string
	pseudoHeaderOrder        []string
	h3PseudoHeaderOrder      []string
	timeoutSeconds           int
	timeoutMilliseconds      int
	followRedirects          bool
	insecureSkipVerify       bool
	forceHttp1               bool
	withRandomTLSExtOrder    bool
	withProtocolRacing       bool
	serverNameOverwrite      string
	requestHostOverride      string
	localAddress             string
	maxIdleConns             int
	maxIdleConnsPerHost      int
	maxConnsPerHost          int
	maxResponseHeaderBytes   int
	writeBufferSize          int
	readBufferSize           int
	idleConnTimeoutSeconds   int
	disableKeepAlives        bool
	disableCompression       bool
	allowEmptyCookies        bool
	disableHTTP3             bool
	disableIPv4              bool
	disableIPv6              bool
	withoutCookieJar         bool
	catchPanics              bool
	withDebug                bool
	streamOutputPath         string
	streamOutputBlockSize    int
	streamOutputEOFSymbol    string
	defaultHeaders           http.Header
	connectHeaders           http.Header
	certificatePinningHosts  map[string][]string
	withDefaultBadPinHandler bool
	requestCookies           []*http.Cookie
	clientCertificates       []tls.Certificate
	clientCertPEMs           [][]byte // raw cert PEM for cache-key parity with buildCacheKey
	clientKeyPEMs            [][]byte // raw key PEM for cache-key parity with buildCacheKey
	customTLSClient          *C.CustomTlsClient // deep-copied to C heap; freed after use
	cacheKeyHash             string            // pre-computed by Python to skip CGO in buildCacheKey
}

// deepCopyRequestOptions converts a C RequestOptions pointer into a
// goroutine-safe requestConfig.  All C strings and byte arrays are copied
// into Go-managed memory.  The caller (RequestAsync) may free the original
// C opts immediately after this function returns.
func deepCopyRequestOptions(opts *C.RequestOptions) (cfg *requestConfig) {
	cfg = &requestConfig{
		method:                 C.GoString(opts.method),
		url:                    C.GoString(opts.url),
		proxy:                  C.GoString(opts.proxy),
		clientIdentifier:       C.GoString(opts.client_identifier),
		timeoutSeconds:         int(opts.timeout_seconds),
		timeoutMilliseconds:    int(opts.timeout_milliseconds),
		followRedirects:        int(opts.follow_redirects) != 0,
		insecureSkipVerify:     int(opts.insecure_skip_verify) != 0,
		forceHttp1:             int(opts.force_http1) != 0,
		withRandomTLSExtOrder:  int(opts.with_random_tls_extension_order) != 0,
		withProtocolRacing:     int(opts.with_protocol_racing) != 0,
		serverNameOverwrite:    C.GoString(opts.server_name_overwrite),
		requestHostOverride:    C.GoString(opts.request_host_override),
		localAddress:           C.GoString(opts.local_address),
		maxIdleConns:           int(opts.max_idle_connections),
		maxIdleConnsPerHost:    int(opts.max_idle_connections_per_host),
		maxConnsPerHost:        int(opts.max_connections_per_host),
		maxResponseHeaderBytes: int(opts.max_response_header_bytes),
		writeBufferSize:        int(opts.write_buffer_size),
		readBufferSize:         int(opts.read_buffer_size),
		idleConnTimeoutSeconds: int(opts.idle_conn_timeout_seconds),
		disableKeepAlives:      int(opts.disable_keep_alives) != 0,
		disableCompression:     int(opts.disable_compression) != 0,
		allowEmptyCookies:      int(opts.allow_empty_cookies) != 0,
		disableHTTP3:           int(opts.disable_http3) != 0,
		disableIPv4:            int(opts.disable_ipv4) != 0,
		disableIPv6:            int(opts.disable_ipv6) != 0,
		withoutCookieJar:       int(opts.without_cookie_jar) != 0,
		catchPanics:            int(opts.catch_panics) != 0,
		withDebug:              int(opts.with_debug) != 0,
		streamOutputBlockSize:  int(opts.stream_output_block_size),
		withDefaultBadPinHandler: int(opts.with_default_bad_pin_handler) != 0,
	}

	// NOTE: the deferred recover MUST be registered AFTER the struct literal.
	// If the struct literal itself panics, cfg is nil (named return) and the
	// caller's nil-guard handles it.  The defer covers panics during the deep
	// copy of customTLSClient and the fields below — only customTLSClient
	// involves C.malloc that would leak, all other fields are Go-managed.
	defer func() {
		if r := recover(); r != nil {
			if cfg.customTLSClient != nil {
				freeCustomTLSClient(cfg.customTLSClient)
			}
			cfg = nil // invalidate so callers see nil regardless of re-panic
			panic(r)
		}
	}()

	// Body — copy to Go heap so the goroutine owns the memory.
	// Python owns the original C buffer and may free it immediately after
	// RequestAsync returns (the goroutine runs asynchronously).  Using
	// unsafe.Slice would alias Python memory, risking use-after-free if
	// Python's async timeout fires before the goroutine reads the body.
	if bl := int(opts.body_len); bl > 0 && opts.body != nil {
		cfg.body = C.GoBytes(unsafe.Pointer(opts.body), C.int(bl))
	}

	// Stream I/O strings (guard against NULL from Python ffi.NULL)
	if opts.stream_output_path != nil {
		cfg.streamOutputPath = C.GoString(opts.stream_output_path)
	}
	if opts.stream_output_eof_symbol != nil {
		cfg.streamOutputEOFSymbol = C.GoString(opts.stream_output_eof_symbol)
	}

	// Headers + order
	if hl := int(opts.headers_len); hl > 0 && opts.headers != nil {
		cfg.headers = cHeadersToHTTP(opts.headers, hl)
	}
	if ol := int(opts.header_order_len); ol > 0 && opts.header_order != nil {
		cfg.headerOrder = cStrSlice(opts.header_order, ol)
	}
	if hpl := int(opts.pseudo_header_order_len); hpl > 0 && opts.pseudo_header_order != nil {
		cfg.pseudoHeaderOrder = cStrSlice(opts.pseudo_header_order, hpl)
	}
	if h3pl := int(opts.h3_pseudo_header_order_len); h3pl > 0 && opts.h3_pseudo_header_order != nil {
		cfg.h3PseudoHeaderOrder = cStrSlice(opts.h3_pseudo_header_order, h3pl)
	}

	// Default / connect headers
	if dhl := int(opts.default_headers_len); dhl > 0 && opts.default_headers != nil {
		cfg.defaultHeaders = cHeadersToHTTP(opts.default_headers, dhl)
	}
	if chl := int(opts.connect_headers_len); chl > 0 && opts.connect_headers != nil {
		cfg.connectHeaders = cHeadersToHTTP(opts.connect_headers, chl)
	}

	// Certificate pinning
	if cpl := int(opts.certificate_pinning_hosts_len); cpl > 0 && opts.certificate_pinning_hosts != nil {
		cfg.certificatePinningHosts = cPinsToMap(opts.certificate_pinning_hosts, cpl)
	}

	// Request cookies
	if rcl := int(opts.request_cookies_len); rcl > 0 && opts.request_cookies != nil {
		rcSlice := unsafe.Slice(opts.request_cookies, rcl)
		cfg.requestCookies = make([]*http.Cookie, rcl)
		for i := 0; i < rcl; i++ {
			cfg.requestCookies[i] = &http.Cookie{
				Name:  C.GoString(rcSlice[i].key),
				Value: C.GoString(rcSlice[i].value),
			}
		}
	}

	// Client certificates (mTLS)
	if ccl := int(opts.client_certificates_len); ccl > 0 && opts.client_certificates != nil {
		cfg.clientCertificates = cClientCerts(opts.client_certificates, ccl)
		// Also store raw PEM bytes for cache-key parity with buildCacheKey.
		// tls.Certificate retains only the parsed DER — the original PEM is
		// lost after X509KeyPair, so we save it here for the hash.
		ccSlice := unsafe.Slice(opts.client_certificates, ccl)
		cfg.clientCertPEMs = make([][]byte, ccl)
		cfg.clientKeyPEMs = make([][]byte, ccl)
		for i := 0; i < ccl; i++ {
			if cpl := int(ccSlice[i].cert_pem_len); cpl > 0 && ccSlice[i].cert_pem != nil {
				cfg.clientCertPEMs[i] = C.GoBytes(unsafe.Pointer(ccSlice[i].cert_pem), C.int(cpl))
			}
			if kpl := int(ccSlice[i].key_pem_len); kpl > 0 && ccSlice[i].key_pem != nil {
				cfg.clientKeyPEMs[i] = C.GoBytes(unsafe.Pointer(ccSlice[i].key_pem), C.int(kpl))
			}
		}
	}

	// CustomTlsClient — deep-copy to C heap so buildCustomProfileFromC can use it.
	// The goroutine frees this copy when done.
	if opts.custom_tls_client != nil {
		cfg.customTLSClient = deepCopyCustomTLSClient(opts.custom_tls_client)
	}

	// Copy the pre-computed cache key hash from Python (avoids CGO calls on cache hit).
	if opts.cache_key_hash != nil {
		cfg.cacheKeyHash = C.GoString(opts.cache_key_hash)
	}

	return cfg
}

// deepCopyCustomTLSClient allocates a new C.CustomTlsClient on the C heap
// and copies all fields (including nested C strings/arrays) from src.
// The caller must call freeCustomTLSClient to release the memory.
func deepCopyCustomTLSClient(src *C.CustomTlsClient) (dst *C.CustomTlsClient) {
	dst = (*C.CustomTlsClient)(C.malloc(C.size_t(unsafe.Sizeof(C.CustomTlsClient{}))))
	*dst = *src // copy scalars from src (connection_flow, record_size_limit, etc.)

	// CRITICAL: null all pointer fields immediately.
	// *dst = *src copied src's pointer values too — if a panic occurs before
	// we overwrite them with our own cStrDup/cStrArrDup allocations, the
	// defer's freeCustomTLSClient would free src's memory (owned by Python),
	// causing a double-free when Python later frees its keep_alive list.
	// Zeroing them first ensures the defer only touches our allocations.
	dst.ja3_string = nil
	dst.h2_settings_keys = nil
	dst.h2_settings_values = nil
	dst.h2_settings_order = nil
	dst.h3_settings_keys = nil
	dst.h3_settings_values = nil
	dst.h3_settings_order = nil
	dst.h3_pseudo_header_order = nil
	dst.header_priority = nil
	dst.cert_compression_algos = nil
	dst.key_share_curves = nil
	dst.alpn_protocols = nil
	dst.alps_protocols = nil
	dst.ech_candidate_payloads = nil
	dst.ech_candidate_cipher_suites = nil
	dst.priority_frames = nil
	dst.pseudo_header_order = nil
	dst.supported_delegated_credentials_algorithms = nil
	dst.supported_signature_algorithms = nil
	dst.supported_versions = nil

	// Panic recovery: if any C.malloc or cStrDup panics partway through
	// the deep copy, we must free the partially-allocated struct to prevent
	// a leak.  After cleanup, re-panic so the caller's defer/recover can
	// convert it to a callback error (Constraint 1 & 3).
	defer func() {
		if r := recover(); r != nil {
			freeCustomTLSClient(dst)
			dst = nil
			panic(r)
		}
	}()

	// Deep-copy all C strings and string arrays
	dst.ja3_string = cStrDup(src.ja3_string)
	dst.h2_settings_order = cStrArrDup(src.h2_settings_order, int(src.h2_settings_order_len))
	dst.h3_settings_order = cStrArrDup(src.h3_settings_order, int(src.h3_settings_order_len))
	dst.h3_pseudo_header_order = cStrArrDup(src.h3_pseudo_header_order, int(src.h3_pseudo_header_order_len))
	dst.cert_compression_algos = cStrArrDup(src.cert_compression_algos, int(src.cert_compression_algos_len))
	dst.key_share_curves = cStrArrDup(src.key_share_curves, int(src.key_share_curves_len))
	dst.alpn_protocols = cStrArrDup(src.alpn_protocols, int(src.alpn_protocols_len))
	dst.alps_protocols = cStrArrDup(src.alps_protocols, int(src.alps_protocols_len))
	dst.pseudo_header_order = cStrArrDup(src.pseudo_header_order, int(src.pseudo_header_order_len))
	dst.supported_delegated_credentials_algorithms = cStrArrDup(src.supported_delegated_credentials_algorithms, int(src.supported_delegated_credentials_algorithms_len))
	dst.supported_signature_algorithms = cStrArrDup(src.supported_signature_algorithms, int(src.supported_signature_algorithms_len))
	dst.supported_versions = cStrArrDup(src.supported_versions, int(src.supported_versions_len))

	// H2 settings keys
	dst.h2_settings_keys = cStrArrDup(src.h2_settings_keys, int(src.h2_settings_len))
	// H2 settings values (plain uint array — alloc and copy)
	if sl := int(src.h2_settings_len); sl > 0 && src.h2_settings_values != nil {
		dst.h2_settings_values = (*C.uint)(C.malloc(C.size_t(sl) * C.size_t(unsafe.Sizeof(C.uint(0)))))
		C.memcpy(unsafe.Pointer(dst.h2_settings_values), unsafe.Pointer(src.h2_settings_values), C.size_t(sl)*C.size_t(unsafe.Sizeof(C.uint(0))))
	}

	// H3 settings keys + values
	dst.h3_settings_keys = cStrArrDup(src.h3_settings_keys, int(src.h3_settings_len))
	if sl := int(src.h3_settings_len); sl > 0 && src.h3_settings_values != nil {
		dst.h3_settings_values = (*C.ulonglong)(C.malloc(C.size_t(sl) * C.size_t(unsafe.Sizeof(C.ulonglong(0)))))
		C.memcpy(unsafe.Pointer(dst.h3_settings_values), unsafe.Pointer(src.h3_settings_values), C.size_t(sl)*C.size_t(unsafe.Sizeof(C.ulonglong(0))))
	}

	// ECH payloads
	if sl := int(src.ech_candidate_payloads_len); sl > 0 && src.ech_candidate_payloads != nil {
		dst.ech_candidate_payloads = (*C.ushort)(C.malloc(C.size_t(sl) * C.size_t(unsafe.Sizeof(C.ushort(0)))))
		C.memcpy(unsafe.Pointer(dst.ech_candidate_payloads), unsafe.Pointer(src.ech_candidate_payloads), C.size_t(sl)*C.size_t(unsafe.Sizeof(C.ushort(0))))
	}

	// ECH cipher suites
	if sl := int(src.ech_candidate_cipher_suites_len); sl > 0 && src.ech_candidate_cipher_suites != nil {
		dst.ech_candidate_cipher_suites = (*C.CandidateCipherSuite)(C.malloc(C.size_t(sl) * C.size_t(unsafe.Sizeof(C.CandidateCipherSuite{}))))
		ecSrc := unsafe.Slice(src.ech_candidate_cipher_suites, sl)
		ecDst := unsafe.Slice(dst.ech_candidate_cipher_suites, sl)
		for i := 0; i < sl; i++ {
			ecDst[i].kdfId = cStrDup(ecSrc[i].kdfId)
			ecDst[i].aeadId = cStrDup(ecSrc[i].aeadId)
		}
	}

	// Priority frames
	if sl := int(src.priority_frames_len); sl > 0 && src.priority_frames != nil {
		dst.priority_frames = (*C.PriorityFrame)(C.malloc(C.size_t(sl) * C.size_t(unsafe.Sizeof(C.PriorityFrame{}))))
		C.memcpy(unsafe.Pointer(dst.priority_frames), unsafe.Pointer(src.priority_frames), C.size_t(sl)*C.size_t(unsafe.Sizeof(C.PriorityFrame{})))
	}

	// Header priority
	if src.header_priority != nil {
		dst.header_priority = (*C.PriorityParam)(C.malloc(C.size_t(unsafe.Sizeof(C.PriorityParam{}))))
		C.memcpy(unsafe.Pointer(dst.header_priority), unsafe.Pointer(src.header_priority), C.size_t(unsafe.Sizeof(C.PriorityParam{})))
	}

	return dst
}

// cStrDup returns a C.CString copy of s, or nil if s is nil/empty.
func cStrDup(s *C.char) *C.char {
	if s == nil {
		return nil
	}
	return C.CString(C.GoString(s))
}

// cStrArrDup deep-copies a C const char** array.
func cStrArrDup(arr **C.char, length int) **C.char {
	if length <= 0 || arr == nil {
		return nil
	}
	copy_ := (**C.char)(C.malloc(C.size_t(length) * C.size_t(unsafe.Sizeof((*C.char)(nil)))))
	slice := unsafe.Slice(copy_, length)
	srcSlice := unsafe.Slice(arr, length)
	for i := 0; i < length; i++ {
		slice[i] = cStrDup(srcSlice[i])
	}
	return copy_
}

// freeCustomTLSClient releases all C heap memory owned by a deepCopyCustomTLSClient result.
func freeCustomTLSClient(ctc *C.CustomTlsClient) {
	if ctc == nil {
		return
	}
	C.free(unsafe.Pointer(ctc.ja3_string))
	freeCStrArr(ctc.h2_settings_order, int(ctc.h2_settings_order_len))
	freeCStrArr(ctc.h3_settings_order, int(ctc.h3_settings_order_len))
	freeCStrArr(ctc.h3_pseudo_header_order, int(ctc.h3_pseudo_header_order_len))
	freeCStrArr(ctc.cert_compression_algos, int(ctc.cert_compression_algos_len))
	freeCStrArr(ctc.key_share_curves, int(ctc.key_share_curves_len))
	freeCStrArr(ctc.alpn_protocols, int(ctc.alpn_protocols_len))
	freeCStrArr(ctc.alps_protocols, int(ctc.alps_protocols_len))
	freeCStrArr(ctc.pseudo_header_order, int(ctc.pseudo_header_order_len))
	freeCStrArr(ctc.supported_delegated_credentials_algorithms, int(ctc.supported_delegated_credentials_algorithms_len))
	freeCStrArr(ctc.supported_signature_algorithms, int(ctc.supported_signature_algorithms_len))
	freeCStrArr(ctc.supported_versions, int(ctc.supported_versions_len))
	freeCStrArr(ctc.h2_settings_keys, int(ctc.h2_settings_len))
	freeCStrArr(ctc.h3_settings_keys, int(ctc.h3_settings_len))
	C.free(unsafe.Pointer(ctc.h2_settings_values))
	C.free(unsafe.Pointer(ctc.h3_settings_values))
	C.free(unsafe.Pointer(ctc.ech_candidate_payloads))
	// Free ECH cipher suites' internal strings
	if sl := int(ctc.ech_candidate_cipher_suites_len); sl > 0 && ctc.ech_candidate_cipher_suites != nil {
		ecSlice := unsafe.Slice(ctc.ech_candidate_cipher_suites, sl)
		for i := 0; i < sl; i++ {
			C.free(unsafe.Pointer(ecSlice[i].kdfId))
			C.free(unsafe.Pointer(ecSlice[i].aeadId))
		}
	}
	C.free(unsafe.Pointer(ctc.ech_candidate_cipher_suites))
	C.free(unsafe.Pointer(ctc.priority_frames))
	C.free(unsafe.Pointer(ctc.header_priority))
	C.free(unsafe.Pointer(ctc))
}

func freeCStrArr(arr **C.char, length int) {
	if length <= 0 || arr == nil {
		return
	}
	slice := unsafe.Slice(arr, length)
	for i := 0; i < length; i++ {
		if slice[i] != nil {
			C.free(unsafe.Pointer(slice[i]))
		}
	}
	C.free(unsafe.Pointer(arr))
}

func buildCacheKey(opts *C.RequestOptions) string {
	ci := C.GoString(opts.client_identifier)
	px := C.GoString(opts.proxy)
	sn := C.GoString(opts.server_name_overwrite)
	la := C.GoString(opts.local_address)

	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d",
		ci, px, sn, la,
		int(opts.insecure_skip_verify),
		int(opts.force_http1),
		int(opts.with_random_tls_extension_order),
		int(opts.with_protocol_racing),
		int(opts.max_idle_connections),
		int(opts.max_idle_connections_per_host),
		int(opts.max_connections_per_host),
		int(opts.max_response_header_bytes),
		int(opts.write_buffer_size),
		int(opts.read_buffer_size),
		int(opts.idle_conn_timeout_seconds),
		int(opts.disable_keep_alives),
		int(opts.disable_compression),
		int(opts.disable_http3),
		int(opts.disable_ipv4),
		int(opts.disable_ipv6),
		int(opts.follow_redirects),
		int(opts.without_cookie_jar),
		int(opts.allow_empty_cookies),
		int(opts.with_default_bad_pin_handler),
		int(opts.timeout_seconds),
		int(opts.timeout_milliseconds),
	)
	// Include pseudo-header orders in the cache key so different orders
	// produce distinct transports.
	phLen := int(opts.pseudo_header_order_len)
	if phLen > 0 && opts.pseudo_header_order != nil {
		phSlice := unsafe.Slice(opts.pseudo_header_order, phLen)
		for i := 0; i < phLen; i++ {
			fmt.Fprintf(h, ":%s", C.GoString(phSlice[i]))
		}
	} else {
		fmt.Fprint(h, ":<default>")
	}
	h3phLen := int(opts.h3_pseudo_header_order_len)
	if h3phLen > 0 && opts.h3_pseudo_header_order != nil {
		h3phSlice := unsafe.Slice(opts.h3_pseudo_header_order, h3phLen)
		for i := 0; i < h3phLen; i++ {
			fmt.Fprintf(h, "#%s", C.GoString(h3phSlice[i]))
		}
	} else {
		fmt.Fprint(h, "#<default>")
	}
	// Default/connect headers affect client behaviour.
	// Collect entries into a flat slice, sort by key, hash — avoids
	// building an intermediate http.Header map that would be discarded
	// on every cache-key computation (including cache hits).
	dhLen := int(opts.default_headers_len)
	if dhLen > 0 && opts.default_headers != nil {
		dhSlice := unsafe.Slice(opts.default_headers, dhLen)
		type dhEntry struct {
			key, val string
		}
		entries := make([]dhEntry, dhLen)
		for i := 0; i < dhLen; i++ {
			entries[i] = dhEntry{C.GoString(dhSlice[i].key), C.GoString(dhSlice[i].value)}
		}
		sort.SliceStable(entries, func(i, j int) bool { return entries[i].key < entries[j].key })
		for _, e := range entries {
			fmt.Fprintf(h, "~dh:%s=%s", e.key, e.val)
		}
	}
	chLen := int(opts.connect_headers_len)
	if chLen > 0 && opts.connect_headers != nil {
		chSlice := unsafe.Slice(opts.connect_headers, chLen)
		type chEntry struct {
			key, val string
		}
		entries := make([]chEntry, chLen)
		for i := 0; i < chLen; i++ {
			entries[i] = chEntry{C.GoString(chSlice[i].key), C.GoString(chSlice[i].value)}
		}
		sort.SliceStable(entries, func(i, j int) bool { return entries[i].key < entries[j].key })
		for _, e := range entries {
			fmt.Fprintf(h, "~ch:%s=%s", e.key, e.val)
		}
	}
	// Certificate pinning — collect into a flat slice, sort by host,
	// hash.  Avoids building an intermediate map that would be discarded
	// on every cache-key computation.
	cpLen := int(opts.certificate_pinning_hosts_len)
	if cpLen > 0 && opts.certificate_pinning_hosts != nil {
		cpSlice := unsafe.Slice(opts.certificate_pinning_hosts, cpLen)
		type cpEntry struct {
			host string
			pins []string
		}
		entries := make([]cpEntry, cpLen)
		for i := 0; i < cpLen; i++ {
			entries[i].host = C.GoString(cpSlice[i].host)
			pl := int(cpSlice[i].pins_len)
			if pl > 0 && cpSlice[i].pins != nil {
				pinSlice := unsafe.Slice(cpSlice[i].pins, pl)
				entries[i].pins = make([]string, pl)
				for j := 0; j < pl; j++ {
					entries[i].pins[j] = C.GoString(pinSlice[j])
				}
			}
		}
		sort.SliceStable(entries, func(i, j int) bool { return entries[i].host < entries[j].host })
		for _, e := range entries {
			fmt.Fprintf(h, "^cp:%s=", e.host)
			for _, p := range e.pins {
				fmt.Fprintf(h, "%s,", p)
			}
		}
	}
	// Client certificates – hash the raw PEM bytes
	ccLen := int(opts.client_certificates_len)
	if ccLen > 0 && opts.client_certificates != nil {
		ccSlice := unsafe.Slice(opts.client_certificates, ccLen)
		for i := 0; i < ccLen; i++ {
			if cpl := int(ccSlice[i].cert_pem_len); cpl > 0 && ccSlice[i].cert_pem != nil {
				certBytes := C.GoBytes(unsafe.Pointer(ccSlice[i].cert_pem), C.int(cpl))
				fmt.Fprintf(h, "|cc:%x", sha256.Sum256(certBytes))
			}
			if kpl := int(ccSlice[i].key_pem_len); kpl > 0 && ccSlice[i].key_pem != nil {
				keyBytes := C.GoBytes(unsafe.Pointer(ccSlice[i].key_pem), C.int(kpl))
				fmt.Fprintf(h, "|ck:%x", sha256.Sum256(keyBytes))
			}
		}
	}
	// Custom TLS client profile
	if opts.custom_tls_client != nil {
		ctc := opts.custom_tls_client
		fmt.Fprintf(h, "|ja3=%s|cf=%d|rsl=%d|sid=%d|h3pp=%d|h3sgf=%d|ah=%d",
			C.GoString(ctc.ja3_string),
			uint32(ctc.connection_flow),
			uint16(ctc.record_size_limit),
			uint32(ctc.stream_id),
			uint32(ctc.h3_priority_param),
			int(ctc.h3_send_grease_frames),
			int(ctc.allow_http),
		)
		// String arrays
		hashStringArray(h, ctc.h2_settings_order, int(ctc.h2_settings_order_len), "|h2so=")
		hashStringArray(h, ctc.h3_settings_order, int(ctc.h3_settings_order_len), "|h3so=")
		hashStringArray(h, ctc.h3_pseudo_header_order, int(ctc.h3_pseudo_header_order_len), "|h3ph=")
		hashStringArray(h, ctc.cert_compression_algos, int(ctc.cert_compression_algos_len), "|cca=")
		hashStringArray(h, ctc.key_share_curves, int(ctc.key_share_curves_len), "|ksc=")
		hashStringArray(h, ctc.alpn_protocols, int(ctc.alpn_protocols_len), "|alpn=")
		hashStringArray(h, ctc.alps_protocols, int(ctc.alps_protocols_len), "|alps=")
		hashStringArray(h, ctc.pseudo_header_order, int(ctc.pseudo_header_order_len), "|ph=")
		hashStringArray(h, ctc.supported_delegated_credentials_algorithms, int(ctc.supported_delegated_credentials_algorithms_len), "|sdca=")
		hashStringArray(h, ctc.supported_signature_algorithms, int(ctc.supported_signature_algorithms_len), "|ssa=")
		hashStringArray(h, ctc.supported_versions, int(ctc.supported_versions_len), "|sv=")
		// H2 settings key-value — sort by key for deterministic cache keys
		if h2l := int(ctc.h2_settings_len); h2l > 0 {
			if ctc.h2_settings_keys != nil && ctc.h2_settings_values != nil {
				sl := unsafe.Slice(ctc.h2_settings_keys, h2l)
				vl := unsafe.Slice(ctc.h2_settings_values, h2l)
				type h2kv struct {
					k string
					v C.uint
				}
				pairs := make([]h2kv, h2l)
				for i := 0; i < h2l; i++ {
					pairs[i] = h2kv{C.GoString(sl[i]), vl[i]}
				}
				sort.Slice(pairs, func(i, j int) bool { return pairs[i].k < pairs[j].k })
				for _, p := range pairs {
					fmt.Fprintf(h, "|h2s:%s=%d", p.k, p.v)
				}
			}
		}
		// H3 settings key-value — sort by key for deterministic cache keys
		if h3l := int(ctc.h3_settings_len); h3l > 0 {
			if ctc.h3_settings_keys != nil && ctc.h3_settings_values != nil {
				sl := unsafe.Slice(ctc.h3_settings_keys, h3l)
				vl := unsafe.Slice(ctc.h3_settings_values, h3l)
				type h3kv struct {
					k string
					v C.ulonglong
				}
				pairs := make([]h3kv, h3l)
				for i := 0; i < h3l; i++ {
					pairs[i] = h3kv{C.GoString(sl[i]), vl[i]}
				}
				sort.Slice(pairs, func(i, j int) bool { return pairs[i].k < pairs[j].k })
				for _, p := range pairs {
					fmt.Fprintf(h, "|h3s:%s=%d", p.k, p.v)
				}
			}
		}
		// ECH payloads
		if epl := int(ctc.ech_candidate_payloads_len); epl > 0 && ctc.ech_candidate_payloads != nil {
			epSlice := unsafe.Slice(ctc.ech_candidate_payloads, epl)
			for i := 0; i < epl; i++ {
				fmt.Fprintf(h, "|echp:%d", epSlice[i])
			}
		}
		// ECH cipher suites — sort by kdfId+aeadId for deterministic cache keys
		if ecl := int(ctc.ech_candidate_cipher_suites_len); ecl > 0 && ctc.ech_candidate_cipher_suites != nil {
			ecSlice := unsafe.Slice(ctc.ech_candidate_cipher_suites, ecl)
			type ecEntry struct {
				kdfId  string
				aeadId string
			}
			entries := make([]ecEntry, ecl)
			for i := 0; i < ecl; i++ {
				entries[i] = ecEntry{C.GoString(ecSlice[i].kdfId), C.GoString(ecSlice[i].aeadId)}
			}
			sort.Slice(entries, func(i, j int) bool {
				if entries[i].kdfId != entries[j].kdfId {
					return entries[i].kdfId < entries[j].kdfId
				}
				return entries[i].aeadId < entries[j].aeadId
			})
			for _, e := range entries {
				fmt.Fprintf(h, "|echcs:%s,%s", e.kdfId, e.aeadId)
			}
		}
		// Priority frames
		if pfl := int(ctc.priority_frames_len); pfl > 0 && ctc.priority_frames != nil {
			pfSlice := unsafe.Slice(ctc.priority_frames, pfl)
			for i := 0; i < pfl; i++ {
				fmt.Fprintf(h, "|pf:%d,%d,%d,%d", pfSlice[i].streamID,
					pfSlice[i].priorityParam.streamDep,
					int(pfSlice[i].priorityParam.exclusive),
					pfSlice[i].priorityParam.weight)
			}
		}
		// Header priority
		if ctc.header_priority != nil {
			hp := ctc.header_priority
			fmt.Fprintf(h, "|hp:%d,%d,%d", hp.streamDep, int(hp.exclusive), hp.weight)
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func hashStringArray(h hash.Hash, arr **C.char, length int, prefix string) {
	if length > 0 && arr != nil {
		slice := unsafe.Slice(arr, length)
		for i := 0; i < length; i++ {
			fmt.Fprintf(h, "%s%s", prefix, C.GoString(slice[i]))
			prefix = ","
		}
	}
}

// b2i converts a bool to 0/1 int for %%d format specifiers.
// Keeps buildCacheKeyFromConfig byte-identical with buildCacheKey.
func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func getOrCreateClient(opts *C.RequestOptions) (tls_client.HttpClient, error) {
	startEviction()

	// Fast path: use Python's pre-computed hash to skip all CGO calls.
	key := ""
	if opts.cache_key_hash != nil {
		key = C.GoString(opts.cache_key_hash)
	}
	if key == "" {
		key = buildCacheKey(opts)
	}

	if entry, ok := clientPool.Load(key); ok {
		if pe, ok := entry.(*poolEntry); ok {
			pe.lastAccess.Store(time.Now().UnixNano())
			return pe.client, nil
		}
	}

	// Serialise construction so we never build two identical clients.
	clientPoolMu.Lock()
	defer clientPoolMu.Unlock()

	// Double-check after acquiring the lock.
	if entry, ok := clientPool.Load(key); ok {
		if pe, ok := entry.(*poolEntry); ok {
			pe.lastAccess.Store(time.Now().UnixNano())
			return pe.client, nil
		}
	}

	client, err := buildClient(opts)
	if err != nil {
		return nil, err
	}

	pe := &poolEntry{client: client}
	pe.lastAccess.Store(time.Now().UnixNano())
	clientPool.Store(key, pe)
	return client, nil
}

func buildClient(opts *C.RequestOptions) (tls_client.HttpClient, error) {
	ci := C.GoString(opts.client_identifier)

	// Build the client profile: use CustomTlsClient if provided, otherwise
	// resolve by identifier (mapped or default).
	var clientProfile profiles.ClientProfile
	if opts.custom_tls_client != nil {
		var profErr error
		clientProfile, profErr = buildCustomProfileFromC(opts.custom_tls_client)
		if profErr != nil {
			return nil, fmt.Errorf("failed to build custom TLS profile: %w", profErr)
		}
	} else {
		clientProfile = profiles.DefaultClientProfile
		if mapped, ok := profiles.MappedTLSClients[ci]; ok {
			clientProfile = mapped
		}
	}

	// If a custom pseudo-header order was provided, create a modified
	// profile that overrides the default order for HTTP/2 and/or HTTP/3.
	phLen := int(opts.pseudo_header_order_len)
	h3phLen := int(opts.h3_pseudo_header_order_len)

	if phLen > 0 || h3phLen > 0 {
		// H3 order: use explicit h3 field if provided, else fall back to H2 order
		h2Order := clientProfile.GetPseudoHeaderOrder()
		h3Order := clientProfile.GetHttp3PseudoHeaderOrder()

		if phLen > 0 && opts.pseudo_header_order != nil {
			phSlice := unsafe.Slice(opts.pseudo_header_order, phLen)
			customH2 := make([]string, phLen)
			for i := 0; i < phLen; i++ {
				customH2[i] = C.GoString(phSlice[i])
			}
			h2Order = customH2
			// If no explicit H3 order, use H2 order for H3 as well
			if h3phLen == 0 || opts.h3_pseudo_header_order == nil {
				h3Order = customH2
			}
		}

		if h3phLen > 0 && opts.h3_pseudo_header_order != nil {
			h3phSlice := unsafe.Slice(opts.h3_pseudo_header_order, h3phLen)
			customH3 := make([]string, h3phLen)
			for i := 0; i < h3phLen; i++ {
				customH3[i] = C.GoString(h3phSlice[i])
			}
			h3Order = customH3
		}

		clientProfile = profiles.NewClientProfile(
			clientProfile.GetClientHelloId(),
			clientProfile.GetSettings(),
			clientProfile.GetSettingsOrder(),
			h2Order,
			clientProfile.GetConnectionFlow(),
			clientProfile.GetPriorities(),
			clientProfile.GetHeaderPriority(),
			clientProfile.GetStreamID(),
			clientProfile.GetAllowHTTP(),
			clientProfile.GetHttp3Settings(),
			clientProfile.GetHttp3SettingsOrder(),
			clientProfile.GetHttp3PriorityParam(),
			h3Order,
			clientProfile.GetHttp3SendGreaseFrames(),
		)
	}

	var options []tls_client.HttpClientOption
	options = append(options, tls_client.WithClientProfile(clientProfile))

	// Timeout: prefer milliseconds if set, else seconds, else default
	var timeoutOption tls_client.HttpClientOption
	if ms := int(opts.timeout_milliseconds); ms > 0 {
		timeoutOption = tls_client.WithTimeoutMilliseconds(ms)
	} else if s := int(opts.timeout_seconds); s > 0 {
		timeoutOption = tls_client.WithTimeoutSeconds(s)
	} else {
		timeoutOption = tls_client.WithTimeoutSeconds(tls_client.DefaultTimeoutSeconds)
	}
	options = append(options, timeoutOption)

	if int(opts.follow_redirects) == 0 {
		options = append(options, tls_client.WithNotFollowRedirects())
	}

	if int(opts.insecure_skip_verify) == 1 {
		options = append(options, tls_client.WithInsecureSkipVerify())
	}

	if int(opts.force_http1) == 1 {
		options = append(options, tls_client.WithForceHttp1())
	}

	if int(opts.with_random_tls_extension_order) == 1 {
		options = append(options, tls_client.WithRandomTLSExtensionOrder())
	}

	if int(opts.disable_http3) == 1 {
		options = append(options, tls_client.WithDisableHttp3())
	}

	if int(opts.with_protocol_racing) == 1 {
		options = append(options, tls_client.WithProtocolRacing())
	}

	if int(opts.disable_ipv6) == 1 {
		options = append(options, tls_client.WithDisableIPV6())
	}

	if int(opts.disable_ipv4) == 1 {
		options = append(options, tls_client.WithDisableIPV4())
	}

	if int(opts.catch_panics) == 1 {
		options = append(options, tls_client.WithCatchPanics())
	}

	if int(opts.with_debug) == 1 {
		options = append(options, tls_client.WithDebug())
	}

	sni := C.GoString(opts.server_name_overwrite)
	if sni != "" {
		options = append(options, tls_client.WithServerNameOverwrite(sni))
	}

	proxy := C.GoString(opts.proxy)
	if proxy != "" {
		options = append(options, tls_client.WithProxyUrl(proxy))
	}

	// Local address (bind to specific interface/IP)
	localAddr := C.GoString(opts.local_address)
	if localAddr != "" {
		addr, addrErr := net.ResolveTCPAddr("", localAddr)
		if addrErr != nil {
			return nil, fmt.Errorf("failed to resolve local address %q: %w", localAddr, addrErr)
		}
		options = append(options, tls_client.WithLocalAddr(*addr))
	}

	transportOpts := &tls_client.TransportOptions{
		MaxIdleConns:           int(opts.max_idle_connections),
		MaxIdleConnsPerHost:    int(opts.max_idle_connections_per_host),
		MaxConnsPerHost:        int(opts.max_connections_per_host),
		MaxResponseHeaderBytes: int64(opts.max_response_header_bytes),
		WriteBufferSize:        int(opts.write_buffer_size),
		ReadBufferSize:         int(opts.read_buffer_size),
		DisableKeepAlives:      int(opts.disable_keep_alives) == 1,
		DisableCompression:     int(opts.disable_compression) == 1,
	}
	// Client certificates for mTLS
	if ccLen := int(opts.client_certificates_len); ccLen > 0 && opts.client_certificates != nil {
		transportOpts.Certificates = cClientCerts(opts.client_certificates, ccLen)
	}
	// Default idle connection timeout of 30s — prevents unbounded
	// connection-pool growth when the caller does not set it explicitly.
	if idleSec := int(opts.idle_conn_timeout_seconds); idleSec > 0 {
		d := time.Duration(idleSec) * time.Second
		transportOpts.IdleConnTimeout = &d
	} else {
		d := 30 * time.Second
		transportOpts.IdleConnTimeout = &d
	}
	options = append(options, tls_client.WithTransportOptions(transportOpts))

	// Cookie jar
	if int(opts.without_cookie_jar) == 1 {
		// No cookie jar at all – cookies are neither stored nor sent
	} else {
		var jarOptions []tls_client.CookieJarOption
		if int(opts.allow_empty_cookies) == 1 {
			jarOptions = append(jarOptions, tls_client.WithAllowEmptyCookies())
		}
		jar := tls_client.NewCookieJar(jarOptions...)
		options = append(options, tls_client.WithCookieJar(jar))
	}

	// Default headers – added to every request when the request itself
	// does not specify a value for the same key.
	if dhLen := int(opts.default_headers_len); dhLen > 0 && opts.default_headers != nil {
		dh := cHeadersToHTTP(opts.default_headers, dhLen)
		options = append(options, tls_client.WithDefaultHeaders(dh))
	}

	// Connect headers – injected into the proxy CONNECT tunnel request.
	if chLen := int(opts.connect_headers_len); chLen > 0 && opts.connect_headers != nil {
		ch := cHeadersToHTTP(opts.connect_headers, chLen)
		options = append(options, tls_client.WithConnectHeaders(ch))
	}

	// Certificate pinning – map host → list of SPKI pin hashes.
	if cpLen := int(opts.certificate_pinning_hosts_len); cpLen > 0 && opts.certificate_pinning_hosts != nil {
		pins := cPinsToMap(opts.certificate_pinning_hosts, cpLen)
		var pinHandler tls_client.BadPinHandlerFunc
		if int(opts.with_default_bad_pin_handler) == 1 {
			pinHandler = tls_client.DefaultBadPinHandler
		}
		options = append(options, tls_client.WithCertificatePinning(pins, pinHandler))
	}

	return tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
}

// cHeadersToHTTP converts a C HttpHeader array to Go http.Header (map[string][]string).
// Multiple entries with the same key are accumulated into a slice.
func cHeadersToHTTP(headers *C.HttpHeader, length int) http.Header {
	h := http.Header{}
	slice := unsafe.Slice(headers, length)
	for i := 0; i < length; i++ {
		k := C.GoString(slice[i].key)
		v := C.GoString(slice[i].value)
		h[k] = append(h[k], v)
	}
	return h
}

// cPinsToMap converts a C PinEntry array to Go map[string][]string for
// use with WithCertificatePinning.
func cPinsToMap(entries *C.PinEntry, length int) map[string][]string {
	m := make(map[string][]string, length)
	slice := unsafe.Slice(entries, length)
	for i := 0; i < length; i++ {
		host := C.GoString(slice[i].host)
		pinLen := int(slice[i].pins_len)
		pins := make([]string, pinLen)
		if pinLen > 0 && slice[i].pins != nil {
			pinSlice := unsafe.Slice(slice[i].pins, pinLen)
			for j := 0; j < pinLen; j++ {
				pins[j] = C.GoString(pinSlice[j])
			}
		}
		m[host] = pins
	}
	return m
}

// cClientCerts converts a C ClientCertificate array to Go []tls.Certificate
// using tls.X509KeyPair to parse each PEM-encoded cert/key pair.
func cClientCerts(entries *C.ClientCertificate, length int) []tls.Certificate {
	if length <= 0 || entries == nil {
		return nil
	}
	certs := make([]tls.Certificate, 0, length)
	slice := unsafe.Slice(entries, length)
	for i := 0; i < length; i++ {
		certPEM := C.GoBytes(unsafe.Pointer(slice[i].cert_pem), C.int(slice[i].cert_pem_len))
		keyPEM := C.GoBytes(unsafe.Pointer(slice[i].key_pem), C.int(slice[i].key_pem_len))
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			continue // skip malformed certs silently
		}
		certs = append(certs, cert)
	}
	return certs
}

// cStrSlice converts a C const char** to Go []string.
func cStrSlice(arr **C.char, length int) []string {
	if length <= 0 || arr == nil {
		return nil
	}
	out := make([]string, length)
	slice := unsafe.Slice(arr, length)
	for i := 0; i < length; i++ {
		out[i] = C.GoString(slice[i])
	}
	return out
}

// buildCustomProfileFromC converts a C CustomTlsClient into a
// profiles.ClientProfile.  Mirrors getCustomTlsClientProfile in
// cffi_src/factory.go.
func buildCustomProfileFromC(ctc *C.CustomTlsClient) (profiles.ClientProfile, error) {
	ja3Str := C.GoString(ctc.ja3_string)
	supportedSigAlgs := cStrSlice(ctc.supported_signature_algorithms, int(ctc.supported_signature_algorithms_len))
	supportedDelCredAlgs := cStrSlice(ctc.supported_delegated_credentials_algorithms, int(ctc.supported_delegated_credentials_algorithms_len))
	supportedVersions := cStrSlice(ctc.supported_versions, int(ctc.supported_versions_len))
	keyShareCurves := cStrSlice(ctc.key_share_curves, int(ctc.key_share_curves_len))
	alpnProtocols := cStrSlice(ctc.alpn_protocols, int(ctc.alpn_protocols_len))
	alpsProtocols := cStrSlice(ctc.alps_protocols, int(ctc.alps_protocols_len))
	certCompressionAlgos := cStrSlice(ctc.cert_compression_algos, int(ctc.cert_compression_algos_len))

	// ECH cipher suites
	var echCipherSuites []tls_client.CandidateCipherSuites
	if ecl := int(ctc.ech_candidate_cipher_suites_len); ecl > 0 && ctc.ech_candidate_cipher_suites != nil {
		ecSlice := unsafe.Slice(ctc.ech_candidate_cipher_suites, ecl)
		echCipherSuites = make([]tls_client.CandidateCipherSuites, ecl)
		for i := 0; i < ecl; i++ {
			echCipherSuites[i] = tls_client.CandidateCipherSuites{
				KdfId:  C.GoString(ecSlice[i].kdfId),
				AeadId: C.GoString(ecSlice[i].aeadId),
			}
		}
	}

	// ECH payloads
	var echPayloads []uint16
	if epl := int(ctc.ech_candidate_payloads_len); epl > 0 && ctc.ech_candidate_payloads != nil {
		epSlice := unsafe.Slice(ctc.ech_candidate_payloads, epl)
		echPayloads = make([]uint16, epl)
		for i := 0; i < epl; i++ {
			echPayloads[i] = uint16(epSlice[i])
		}
	}

	specFactory, err := tls_client.GetSpecFactoryFromJa3String(
		ja3Str, supportedSigAlgs, supportedDelCredAlgs,
		supportedVersions, keyShareCurves, alpnProtocols,
		alpsProtocols, echCipherSuites, echPayloads,
		certCompressionAlgos, uint16(ctc.record_size_limit),
	)
	if err != nil {
		var zero profiles.ClientProfile
		return zero, fmt.Errorf("JA3 spec factory: %w", err)
	}

	clientHelloId := tls.ClientHelloID{
		Client:      "Custom",
		Version:     "1",
		Seed:        nil,
		SpecFactory: specFactory,
	}

	// H2 settings – resolve string keys to SettingID
	resolvedH2Settings := make(map[http2.SettingID]uint32)
	if h2l := int(ctc.h2_settings_len); h2l > 0 && ctc.h2_settings_keys != nil && ctc.h2_settings_values != nil {
		keySlice := unsafe.Slice(ctc.h2_settings_keys, h2l)
		valSlice := unsafe.Slice(ctc.h2_settings_values, h2l)
		for i := 0; i < h2l; i++ {
			k := C.GoString(keySlice[i])
			if resolvedKey, ok := tls_client.H2SettingsMap[k]; ok {
				resolvedH2Settings[resolvedKey] = uint32(valSlice[i])
			}
		}
	}

	var resolvedH2SettingsOrder []http2.SettingID
	if h2ol := int(ctc.h2_settings_order_len); h2ol > 0 && ctc.h2_settings_order != nil {
		orderSlice := unsafe.Slice(ctc.h2_settings_order, h2ol)
		for i := 0; i < h2ol; i++ {
			k := C.GoString(orderSlice[i])
			if resolvedKey, ok := tls_client.H2SettingsMap[k]; ok {
				resolvedH2SettingsOrder = append(resolvedH2SettingsOrder, resolvedKey)
			}
		}
	}

	// H3 settings
	resolvedH3Settings := make(map[uint64]uint64)
	if h3l := int(ctc.h3_settings_len); h3l > 0 && ctc.h3_settings_keys != nil && ctc.h3_settings_values != nil {
		keySlice := unsafe.Slice(ctc.h3_settings_keys, h3l)
		valSlice := unsafe.Slice(ctc.h3_settings_values, h3l)
		for i := 0; i < h3l; i++ {
			k := C.GoString(keySlice[i])
			if resolvedKey, ok := tls_client.H3SettingsMap[k]; ok {
				resolvedH3Settings[resolvedKey] = uint64(valSlice[i])
			}
		}
	}

	var resolvedH3SettingsOrder []uint64
	if h3ol := int(ctc.h3_settings_order_len); h3ol > 0 && ctc.h3_settings_order != nil {
		orderSlice := unsafe.Slice(ctc.h3_settings_order, h3ol)
		for i := 0; i < h3ol; i++ {
			k := C.GoString(orderSlice[i])
			if resolvedKey, ok := tls_client.H3SettingsMap[k]; ok {
				resolvedH3SettingsOrder = append(resolvedH3SettingsOrder, resolvedKey)
			}
		}
	}

	// Priority frames
	var priorityFrames []http2.Priority
	if pfl := int(ctc.priority_frames_len); pfl > 0 && ctc.priority_frames != nil {
		pfSlice := unsafe.Slice(ctc.priority_frames, pfl)
		priorityFrames = make([]http2.Priority, pfl)
		for i := 0; i < pfl; i++ {
			priorityFrames[i] = http2.Priority{
				StreamID: uint32(pfSlice[i].streamID),
				PriorityParam: http2.PriorityParam{
					StreamDep: uint32(pfSlice[i].priorityParam.streamDep),
					Exclusive: pfSlice[i].priorityParam.exclusive != 0,
					Weight:    uint8(pfSlice[i].priorityParam.weight),
				},
			}
		}
	}

	// Header priority
	var headerPriority *http2.PriorityParam
	if ctc.header_priority != nil {
		headerPriority = &http2.PriorityParam{
			StreamDep: uint32(ctc.header_priority.streamDep),
			Exclusive: ctc.header_priority.exclusive != 0,
			Weight:    uint8(ctc.header_priority.weight),
		}
	}

	pseudoHeaderOrder := cStrSlice(ctc.pseudo_header_order, int(ctc.pseudo_header_order_len))
	h3PseudoHeaderOrder := cStrSlice(ctc.h3_pseudo_header_order, int(ctc.h3_pseudo_header_order_len))

	return profiles.NewClientProfile(
		clientHelloId,
		resolvedH2Settings,
		resolvedH2SettingsOrder,
		pseudoHeaderOrder,
		uint32(ctc.connection_flow),
		priorityFrames,
		headerPriority,
		uint32(ctc.stream_id),
		int(ctc.allow_http) != 0,
		resolvedH3Settings,
		resolvedH3SettingsOrder,
		uint32(ctc.h3_priority_param),
		h3PseudoHeaderOrder,
		int(ctc.h3_send_grease_frames) != 0,
	), nil
}

// ---------------------------------------------------------------------------
// Go-native HTTP execution — shared between sync ExecuteRequest and async RequestAsync.
// These functions operate on Go types (requestConfig) and are goroutine-safe.
// ---------------------------------------------------------------------------

func buildCacheKeyFromConfig(cfg *requestConfig) string {
	h := sha256.New()
	// Match buildCacheKey format — use %%d with int(bool) so sync and async
	// paths produce identical cache keys when cache_key_hash is not provided.
	fmt.Fprintf(h, "%s|%s|%s|%s|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d",
		cfg.clientIdentifier, cfg.proxy, cfg.serverNameOverwrite, cfg.localAddress,
		b2i(cfg.insecureSkipVerify), b2i(cfg.forceHttp1), b2i(cfg.withRandomTLSExtOrder), b2i(cfg.withProtocolRacing),
		cfg.maxIdleConns, cfg.maxIdleConnsPerHost, cfg.maxConnsPerHost,
		cfg.maxResponseHeaderBytes, cfg.writeBufferSize, cfg.readBufferSize,
		cfg.idleConnTimeoutSeconds, b2i(cfg.disableKeepAlives), b2i(cfg.disableCompression),
		b2i(cfg.disableHTTP3), b2i(cfg.disableIPv4), b2i(cfg.disableIPv6), b2i(cfg.followRedirects),
		b2i(cfg.withoutCookieJar), b2i(cfg.allowEmptyCookies), b2i(cfg.withDefaultBadPinHandler),
		cfg.timeoutSeconds, cfg.timeoutMilliseconds,
	)
	if len(cfg.pseudoHeaderOrder) > 0 {
		for _, s := range cfg.pseudoHeaderOrder {
			fmt.Fprintf(h, ":%s", s)
		}
	} else {
		fmt.Fprint(h, ":<default>")
	}
	if len(cfg.h3PseudoHeaderOrder) > 0 {
		for _, s := range cfg.h3PseudoHeaderOrder {
			fmt.Fprintf(h, "#%s", s)
		}
	} else {
		fmt.Fprint(h, "#<default>")
	}
	// Sort map keys for deterministic cache keys
	sortedHeaderKeys := make([]string, 0, len(cfg.defaultHeaders))
	for k := range cfg.defaultHeaders {
		sortedHeaderKeys = append(sortedHeaderKeys, k)
	}
	sort.Strings(sortedHeaderKeys)
	for _, k := range sortedHeaderKeys {
		for _, v := range cfg.defaultHeaders[k] {
			fmt.Fprintf(h, "~dh:%s=%s", k, v)
		}
	}
	sortedConnectKeys := make([]string, 0, len(cfg.connectHeaders))
	for k := range cfg.connectHeaders {
		sortedConnectKeys = append(sortedConnectKeys, k)
	}
	sort.Strings(sortedConnectKeys)
	for _, k := range sortedConnectKeys {
		for _, v := range cfg.connectHeaders[k] {
			fmt.Fprintf(h, "~ch:%s=%s", k, v)
		}
	}
	sortedPinHosts := make([]string, 0, len(cfg.certificatePinningHosts))
	for host := range cfg.certificatePinningHosts {
		sortedPinHosts = append(sortedPinHosts, host)
	}
	sort.Strings(sortedPinHosts)
	for _, host := range sortedPinHosts {
		fmt.Fprintf(h, "^cp:%s=", host)
		for _, p := range cfg.certificatePinningHosts[host] {
			fmt.Fprintf(h, "%s,", p)
		}
	}
	for i := range cfg.clientCertPEMs {
		if len(cfg.clientCertPEMs[i]) > 0 {
			fmt.Fprintf(h, "|cc:%x", sha256.Sum256(cfg.clientCertPEMs[i]))
		}
		if len(cfg.clientKeyPEMs[i]) > 0 {
			fmt.Fprintf(h, "|ck:%x", sha256.Sum256(cfg.clientKeyPEMs[i]))
		}
	}
	// Hash custom TLS client configuration (mirrors buildCacheKey)
	if cfg.customTLSClient != nil {
		ctc := cfg.customTLSClient
		fmt.Fprintf(h, "|ja3=%s|cf=%d|rsl=%d|sid=%d|h3pp=%d|h3sgf=%d|ah=%d",
			C.GoString(ctc.ja3_string),
			uint32(ctc.connection_flow),
			uint16(ctc.record_size_limit),
			uint32(ctc.stream_id),
			uint32(ctc.h3_priority_param),
			int(ctc.h3_send_grease_frames),
			int(ctc.allow_http),
		)
		hashStringArray(h, ctc.h2_settings_order, int(ctc.h2_settings_order_len), "|h2so=")
		hashStringArray(h, ctc.h3_settings_order, int(ctc.h3_settings_order_len), "|h3so=")
		hashStringArray(h, ctc.h3_pseudo_header_order, int(ctc.h3_pseudo_header_order_len), "|h3ph=")
		hashStringArray(h, ctc.cert_compression_algos, int(ctc.cert_compression_algos_len), "|cca=")
		hashStringArray(h, ctc.key_share_curves, int(ctc.key_share_curves_len), "|ksc=")
		hashStringArray(h, ctc.alpn_protocols, int(ctc.alpn_protocols_len), "|alpn=")
		hashStringArray(h, ctc.alps_protocols, int(ctc.alps_protocols_len), "|alps=")
		hashStringArray(h, ctc.pseudo_header_order, int(ctc.pseudo_header_order_len), "|ph=")
		hashStringArray(h, ctc.supported_delegated_credentials_algorithms, int(ctc.supported_delegated_credentials_algorithms_len), "|sdca=")
		hashStringArray(h, ctc.supported_signature_algorithms, int(ctc.supported_signature_algorithms_len), "|ssa=")
		hashStringArray(h, ctc.supported_versions, int(ctc.supported_versions_len), "|sv=")
		if h2l := int(ctc.h2_settings_len); h2l > 0 {
			if ctc.h2_settings_keys != nil && ctc.h2_settings_values != nil {
				sl := unsafe.Slice(ctc.h2_settings_keys, h2l)
				vl := unsafe.Slice(ctc.h2_settings_values, h2l)
				type h2kv struct {
					k string
					v C.uint
				}
				pairs := make([]h2kv, h2l)
				for i := 0; i < h2l; i++ {
					pairs[i] = h2kv{C.GoString(sl[i]), vl[i]}
				}
				sort.Slice(pairs, func(i, j int) bool { return pairs[i].k < pairs[j].k })
				for _, p := range pairs {
					fmt.Fprintf(h, "|h2s:%s=%d", p.k, p.v)
				}
			}
		}
		if h3l := int(ctc.h3_settings_len); h3l > 0 {
			if ctc.h3_settings_keys != nil && ctc.h3_settings_values != nil {
				sl := unsafe.Slice(ctc.h3_settings_keys, h3l)
				vl := unsafe.Slice(ctc.h3_settings_values, h3l)
				type h3kv struct {
					k string
					v C.ulonglong
				}
				pairs := make([]h3kv, h3l)
				for i := 0; i < h3l; i++ {
					pairs[i] = h3kv{C.GoString(sl[i]), vl[i]}
				}
				sort.Slice(pairs, func(i, j int) bool { return pairs[i].k < pairs[j].k })
				for _, p := range pairs {
					fmt.Fprintf(h, "|h3s:%s=%d", p.k, p.v)
				}
			}
		}
		if epl := int(ctc.ech_candidate_payloads_len); epl > 0 && ctc.ech_candidate_payloads != nil {
			epSlice := unsafe.Slice(ctc.ech_candidate_payloads, epl)
			for i := 0; i < epl; i++ {
				fmt.Fprintf(h, "|echp:%d", epSlice[i])
			}
		}
		if ecl := int(ctc.ech_candidate_cipher_suites_len); ecl > 0 && ctc.ech_candidate_cipher_suites != nil {
			ecSlice := unsafe.Slice(ctc.ech_candidate_cipher_suites, ecl)
			type ecEntry struct {
				kdfId  string
				aeadId string
			}
			entries := make([]ecEntry, ecl)
			for i := 0; i < ecl; i++ {
				entries[i] = ecEntry{C.GoString(ecSlice[i].kdfId), C.GoString(ecSlice[i].aeadId)}
			}
			sort.Slice(entries, func(i, j int) bool {
				if entries[i].kdfId != entries[j].kdfId {
					return entries[i].kdfId < entries[j].kdfId
				}
				return entries[i].aeadId < entries[j].aeadId
			})
			for _, e := range entries {
				fmt.Fprintf(h, "|echcs:%s,%s", e.kdfId, e.aeadId)
			}
		}
		if pfl := int(ctc.priority_frames_len); pfl > 0 && ctc.priority_frames != nil {
			pfSlice := unsafe.Slice(ctc.priority_frames, pfl)
			for i := 0; i < pfl; i++ {
				fmt.Fprintf(h, "|pf:%d,%d,%d,%d", pfSlice[i].streamID,
					pfSlice[i].priorityParam.streamDep,
					int(pfSlice[i].priorityParam.exclusive),
					pfSlice[i].priorityParam.weight)
			}
		}
		if ctc.header_priority != nil {
			hp := ctc.header_priority
			fmt.Fprintf(h, "|hp:%d,%d,%d", hp.streamDep, int(hp.exclusive), hp.weight)
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func getOrCreateClientFromConfig(cfg *requestConfig) (tls_client.HttpClient, error) {
	startEviction()
	key := cfg.cacheKeyHash
	if key == "" {
		key = buildCacheKeyFromConfig(cfg)
	}
	if entry, ok := clientPool.Load(key); ok {
		if pe, ok := entry.(*poolEntry); ok {
			pe.lastAccess.Store(time.Now().UnixNano())
			return pe.client, nil
		}
	}
	clientPoolMu.Lock()
	defer clientPoolMu.Unlock()
	if entry, ok := clientPool.Load(key); ok {
		if pe, ok := entry.(*poolEntry); ok {
			pe.lastAccess.Store(time.Now().UnixNano())
			return pe.client, nil
		}
	}
	client, err := buildClientFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	pe := &poolEntry{client: client}
	pe.lastAccess.Store(time.Now().UnixNano())
	clientPool.Store(key, pe)
	return client, nil
}

func buildClientFromConfig(cfg *requestConfig) (tls_client.HttpClient, error) {
	var clientProfile profiles.ClientProfile
	if cfg.customTLSClient != nil {
		var profErr error
		clientProfile, profErr = buildCustomProfileFromC(cfg.customTLSClient)
		if profErr != nil {
			return nil, fmt.Errorf("failed to build custom TLS profile: %w", profErr)
		}
	} else {
		clientProfile = profiles.DefaultClientProfile
		if mapped, ok := profiles.MappedTLSClients[cfg.clientIdentifier]; ok {
			clientProfile = mapped
		}
	}

	if len(cfg.pseudoHeaderOrder) > 0 || len(cfg.h3PseudoHeaderOrder) > 0 {
		h2Order := clientProfile.GetPseudoHeaderOrder()
		h3Order := clientProfile.GetHttp3PseudoHeaderOrder()
		if len(cfg.pseudoHeaderOrder) > 0 {
			h2Order = cfg.pseudoHeaderOrder
			if len(cfg.h3PseudoHeaderOrder) == 0 {
				h3Order = cfg.pseudoHeaderOrder
			}
		}
		if len(cfg.h3PseudoHeaderOrder) > 0 {
			h3Order = cfg.h3PseudoHeaderOrder
		}
		clientProfile = profiles.NewClientProfile(
			clientProfile.GetClientHelloId(), clientProfile.GetSettings(),
			clientProfile.GetSettingsOrder(), h2Order, clientProfile.GetConnectionFlow(),
			clientProfile.GetPriorities(), clientProfile.GetHeaderPriority(),
			clientProfile.GetStreamID(), clientProfile.GetAllowHTTP(),
			clientProfile.GetHttp3Settings(), clientProfile.GetHttp3SettingsOrder(),
			clientProfile.GetHttp3PriorityParam(), h3Order,
			clientProfile.GetHttp3SendGreaseFrames(),
		)
	}

	var options []tls_client.HttpClientOption
	options = append(options, tls_client.WithClientProfile(clientProfile))

	if cfg.timeoutMilliseconds > 0 {
		options = append(options, tls_client.WithTimeoutMilliseconds(cfg.timeoutMilliseconds))
	} else if cfg.timeoutSeconds > 0 {
		options = append(options, tls_client.WithTimeoutSeconds(cfg.timeoutSeconds))
	} else {
		options = append(options, tls_client.WithTimeoutSeconds(tls_client.DefaultTimeoutSeconds))
	}
	if !cfg.followRedirects {
		options = append(options, tls_client.WithNotFollowRedirects())
	}
	if cfg.insecureSkipVerify {
		options = append(options, tls_client.WithInsecureSkipVerify())
	}
	if cfg.forceHttp1 {
		options = append(options, tls_client.WithForceHttp1())
	}
	if cfg.withRandomTLSExtOrder {
		options = append(options, tls_client.WithRandomTLSExtensionOrder())
	}
	if cfg.disableHTTP3 {
		options = append(options, tls_client.WithDisableHttp3())
	}
	if cfg.withProtocolRacing {
		options = append(options, tls_client.WithProtocolRacing())
	}
	if cfg.disableIPv6 {
		options = append(options, tls_client.WithDisableIPV6())
	}
	if cfg.disableIPv4 {
		options = append(options, tls_client.WithDisableIPV4())
	}
	if cfg.catchPanics {
		options = append(options, tls_client.WithCatchPanics())
	}
	if cfg.withDebug {
		options = append(options, tls_client.WithDebug())
	}
	if cfg.serverNameOverwrite != "" {
		options = append(options, tls_client.WithServerNameOverwrite(cfg.serverNameOverwrite))
	}
	if cfg.proxy != "" {
		options = append(options, tls_client.WithProxyUrl(cfg.proxy))
	}
	if cfg.localAddress != "" {
		addr, addrErr := net.ResolveTCPAddr("", cfg.localAddress)
		if addrErr != nil {
			return nil, fmt.Errorf("failed to resolve local address %q: %w", cfg.localAddress, addrErr)
		}
		options = append(options, tls_client.WithLocalAddr(*addr))
	}

	transportOpts := &tls_client.TransportOptions{
		MaxIdleConns:           cfg.maxIdleConns,
		MaxIdleConnsPerHost:    cfg.maxIdleConnsPerHost,
		MaxConnsPerHost:        cfg.maxConnsPerHost,
		MaxResponseHeaderBytes: int64(cfg.maxResponseHeaderBytes),
		WriteBufferSize:        cfg.writeBufferSize,
		ReadBufferSize:         cfg.readBufferSize,
		DisableKeepAlives:      cfg.disableKeepAlives,
		DisableCompression:     cfg.disableCompression,
	}
	if len(cfg.clientCertificates) > 0 {
		transportOpts.Certificates = cfg.clientCertificates
	}
	// Default idle connection timeout of 30s — prevents unbounded
	// connection-pool growth when the caller does not set it explicitly.
	if cfg.idleConnTimeoutSeconds > 0 {
		d := time.Duration(cfg.idleConnTimeoutSeconds) * time.Second
		transportOpts.IdleConnTimeout = &d
	} else {
		d := 30 * time.Second
		transportOpts.IdleConnTimeout = &d
	}
	options = append(options, tls_client.WithTransportOptions(transportOpts))

	if cfg.withoutCookieJar {
		// No cookie jar
	} else {
		var jarOptions []tls_client.CookieJarOption
		if cfg.allowEmptyCookies {
			jarOptions = append(jarOptions, tls_client.WithAllowEmptyCookies())
		}
		jar := tls_client.NewCookieJar(jarOptions...)
		options = append(options, tls_client.WithCookieJar(jar))
	}
	if len(cfg.defaultHeaders) > 0 {
		options = append(options, tls_client.WithDefaultHeaders(cfg.defaultHeaders))
	}
	if len(cfg.connectHeaders) > 0 {
		options = append(options, tls_client.WithConnectHeaders(cfg.connectHeaders))
	}
	if len(cfg.certificatePinningHosts) > 0 {
		var pinHandler tls_client.BadPinHandlerFunc
		if cfg.withDefaultBadPinHandler {
			pinHandler = tls_client.DefaultBadPinHandler
		}
		options = append(options, tls_client.WithCertificatePinning(cfg.certificatePinningHosts, pinHandler))
	}

	return tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
}

// executeRequestFromConfig performs the full HTTP request cycle (client lookup,
// request construction, execution, body reading, response populating) from a
// Go requestConfig.  Returns a C.ResponseResult allocated on the C heap — the
// caller owns it and must call FreeResponse to release it.
func executeRequestFromConfig(cfg *requestConfig) *C.ResponseResult {
	result := (*C.ResponseResult)(C.malloc(C.size_t(unsafe.Sizeof(C.ResponseResult{}))))
	if result == nil {
		return nil
	}
	*result = C.ResponseResult{}

	defer func() {
		if r := recover(); r != nil {
			if result.err_msg != nil {
				C.free(unsafe.Pointer(result.err_msg))
				result.err_msg = nil
			}
			result.err_msg = C.CString(fmt.Sprintf("go panic: %v", r))
			result.status_code = 0
		}
	}()

	client, err := getOrCreateClientFromConfig(cfg)
	if err != nil {
		result.err_msg = C.CString(fmt.Sprintf("failed to obtain client: %v", err))
		return result
	}

	var bodyReader io.Reader
	if len(cfg.body) > 0 {
		bodyReader = bytes.NewReader(cfg.body)
	}

	req, err := http.NewRequest(cfg.method, cfg.url, bodyReader)
	if err != nil {
		result.err_msg = C.CString(fmt.Sprintf("failed to create request: %v", err))
		return result
	}

	if cfg.requestHostOverride != "" {
		req.Host = cfg.requestHostOverride
	}

	if len(cfg.headers) > 0 {
		if len(cfg.headerOrder) > 0 {
			cfg.headers[http.HeaderOrderKey] = cfg.headerOrder
		}
		req.Header = cfg.headers
	}

	// Attach per-request cookies directly to the request rather than
	// injecting them into the shared client CookieJar (which would cause
	// jar bloat and data races across concurrent requests).
	if len(cfg.requestCookies) > 0 {
		for _, c := range cfg.requestCookies {
			req.AddCookie(c)
		}
	}

	resp, reqErr := client.Do(req)
	if reqErr != nil {
		result.err_msg = C.CString(fmt.Sprintf("request failed: %v", reqErr))
		return result
	}
	defer resp.Body.Close()

	if !cfg.disableCompression && !resp.Uncompressed {
		ce := resp.Header.Get("Content-Encoding")
		resp.Body = http.DecompressBodyByType(resp.Body, ce)
	}

	var respBody []byte
	var readErr error
	var bodyDirectToC bool
	if cfg.streamOutputPath != "" {
		respBody, readErr = readBodyStreamToFileFromConfig(resp.Body, cfg)
	} else if cBody, cLen, cErr := readBodyToCHeap(resp.Body, resp.ContentLength); cBody != nil {
		// Fast path: body read directly into C heap — no Go intermediate.
		result.body = cBody
		result.body_len = C.int(cLen)
		bodyDirectToC = true
	} else if cErr != nil {
		result.err_msg = C.CString(fmt.Sprintf("failed to read response body: %v", cErr))
		return result
	} else {
		respBody, readErr = readAllPooled(resp.Body)
	}
	if !bodyDirectToC {
		if readErr != nil {
			result.err_msg = C.CString(fmt.Sprintf("failed to read response body: %v", readErr))
			return result
		}
		result.body_len = C.int(len(respBody))
		if len(respBody) > 0 {
			cBody := C.malloc(C.size_t(len(respBody)))
			if cBody == nil {
				result.err_msg = C.CString("failed to allocate memory for response body")
				return result
			}
			cSlice := unsafe.Slice((*byte)(cBody), len(respBody))
			copy(cSlice, respBody)
			result.body = (*C.char)(cBody)
		}
	}

	result.status_code = C.int(resp.StatusCode)

	if resp.Request != nil && resp.Request.URL != nil {
		result.target_url = C.CString(resp.Request.URL.String())
	}
	result.used_protocol = C.CString(resp.Proto)

	packResponseArena(result, resp.Header, resp.Cookies())
	if result.err_msg != nil {
		return result
	}

	return result
}

func readBodyStreamToFileFromConfig(body io.Reader, cfg *requestConfig) ([]byte, error) {
	f, err := os.OpenFile(cfg.streamOutputPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("stream: cannot open output file: %w", err)
	}
	defer f.Close()

	blockSize := 8192
	if cfg.streamOutputBlockSize > 0 {
		blockSize = cfg.streamOutputBlockSize
	}
	buf := make([]byte, blockSize)
	for {
		n, readErr := body.Read(buf)
		if n > 0 {
			if _, writeErr := f.Write(buf[:n]); writeErr != nil {
				return nil, fmt.Errorf("stream: write error: %w", writeErr)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("stream: read error: %w", readErr)
		}
	}
	if cfg.streamOutputEOFSymbol != "" {
		f.Write([]byte(cfg.streamOutputEOFSymbol))
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// Exported C functions
// ---------------------------------------------------------------------------

// readBodyStreamToFile reads the response body in chunks and writes them to
// the file specified by opts.stream_output_path.  Returns nil body bytes —
// the payload lives exclusively on disk.
func readBodyStreamToFile(body io.Reader, opts *C.RequestOptions) ([]byte, error) {
	path := C.GoString(opts.stream_output_path)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("stream: cannot open output file: %w", err)
	}
	defer f.Close()

	blockSize := 8192 // default 8 KB
	if bs := int(opts.stream_output_block_size); bs > 0 {
		blockSize = bs
	}
	buf := make([]byte, blockSize)

	for {
		n, readErr := body.Read(buf)
		if n > 0 {
			if _, writeErr := f.Write(buf[:n]); writeErr != nil {
				return nil, fmt.Errorf("stream: write error: %w", writeErr)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("stream: read error: %w", readErr)
		}
	}

	// Optional EOF marker – guard against NULL pointer.
	var eof string
	if opts.stream_output_eof_symbol != nil {
		eof = C.GoString(opts.stream_output_eof_symbol)
	}
	if eof != "" {
		f.Write([]byte(eof))
	}

	return nil, nil
}

// packResponseArena allocates a single combined HttpHeader array and a single
// C string arena containing all header key+value and cookie name+value strings.
// Every key/value pointer in the HttpHeader array points into the arena.
// Headers occupy indices [0, headerCount) and cookies occupy
// [headerCount, headerCount+cookieCount) within the same allocation.
// On success, sets result.response_headers, .cookies, .response_headers_len,
// .cookies_len, and ._resp_strings.  Returns false on allocation failure
// (result.err_msg is set).
func packResponseArena(result *C.ResponseResult, respHeaders http.Header, respCookies []*http.Cookie) {
	// Phase 1: count entries and total string bytes (including \0 terminators).
	headerEntries := 0
	headerBytes := 0
	for key, values := range respHeaders {
		for _, val := range values {
			headerEntries++
			headerBytes += len(key) + 1 + len(val) + 1
		}
	}
	cookieCount := len(respCookies)
	cookieBytes := 0
	for _, c := range respCookies {
		cookieBytes += len(c.Name) + 1 + len(c.Value) + 1
	}
	totalEntries := headerEntries + cookieCount
	if totalEntries == 0 {
		return // nothing to do
	}

	// Phase 2: allocate combined HttpHeader array + string arena.
	entryArr := (*C.HttpHeader)(C.calloc(C.size_t(totalEntries), C.size_t(unsafe.Sizeof(C.HttpHeader{}))))
	if entryArr == nil {
		result.err_msg = C.CString("failed to allocate response header array")
		return
	}
	// Assign IMMEDIATELY so FreeResponse can release the memory if Phase 3 panics.
	result.response_headers = entryArr

	totalStrBytes := headerBytes + cookieBytes
	var arena *C.char
	if totalStrBytes > 0 {
		arena = (*C.char)(C.malloc(C.size_t(totalStrBytes)))
		if arena == nil {
			C.free(unsafe.Pointer(entryArr))
			result.response_headers = nil
			result.err_msg = C.CString("failed to allocate response string arena")
			return
		}
		// Assign IMMEDIATELY so FreeResponse can release the memory if Phase 3 panics.
		result._resp_strings = arena
	}

	// Phase 3: fill headers and strings.
	entrySlice := unsafe.Slice(entryArr, totalEntries)
	entryIdx := 0
	if arena != nil {
		arenaBase := uintptr(unsafe.Pointer(arena))
		offset := 0
		for key, values := range respHeaders {
			for _, val := range values {
				// Copy key
				dst := (*byte)(unsafe.Pointer(arenaBase + uintptr(offset)))
				keySlice := unsafe.Slice(dst, len(key)+1)
				copy(keySlice, key)
				keySlice[len(key)] = 0
				entrySlice[entryIdx].key = (*C.char)(unsafe.Pointer(dst))
				offset += len(key) + 1
				// Copy value
				dst = (*byte)(unsafe.Pointer(arenaBase + uintptr(offset)))
				valSlice := unsafe.Slice(dst, len(val)+1)
				copy(valSlice, val)
				valSlice[len(val)] = 0
				entrySlice[entryIdx].value = (*C.char)(unsafe.Pointer(dst))
				offset += len(val) + 1
				entryIdx++
			}
		}
		// Fill cookies
		if cookieCount > 0 {
			cookieSlice := entrySlice[headerEntries:]
			for i, c := range respCookies {
				dst := (*byte)(unsafe.Pointer(arenaBase + uintptr(offset)))
				nameSlice := unsafe.Slice(dst, len(c.Name)+1)
				copy(nameSlice, c.Name)
				nameSlice[len(c.Name)] = 0
				cookieSlice[i].key = (*C.char)(unsafe.Pointer(dst))
				offset += len(c.Name) + 1
				dst = (*byte)(unsafe.Pointer(arenaBase + uintptr(offset)))
				valSlice := unsafe.Slice(dst, len(c.Value)+1)
				copy(valSlice, c.Value)
				valSlice[len(c.Value)] = 0
				cookieSlice[i].value = (*C.char)(unsafe.Pointer(dst))
				offset += len(c.Value) + 1
			}
		}
	}

	result.response_headers_len = C.int(headerEntries)
	if cookieCount > 0 {
		result.cookies = &entrySlice[headerEntries]
		result.cookies_len = C.int(cookieCount)
	}
}

//export ExecuteRequest
func ExecuteRequest(opts *C.RequestOptions) *C.ResponseResult {
	// Heap-allocate the result so the pointer remains valid after return.
	result := (*C.ResponseResult)(C.malloc(C.size_t(unsafe.Sizeof(C.ResponseResult{}))))
	if result == nil {
		return nil
	}
	*result = C.ResponseResult{}

	// Catch every panic inside Go and convert it into a C-accessible error
	// string so the Python side never sees a hard crash.
	defer func() {
		if r := recover(); r != nil {
			// Free any previously allocated error message to prevent leaks
			// (e.g. if a C.CString was already set before the panic).
			if result.err_msg != nil {
				C.free(unsafe.Pointer(result.err_msg))
				result.err_msg = nil
			}
			result.err_msg = C.CString(fmt.Sprintf("go panic: %v", r))
			result.status_code = 0
		}
	}()

	if opts == nil {
		result.err_msg = C.CString("RequestOptions pointer is nil")
		return result
	}

	client, err := getOrCreateClient(opts)
	if err != nil {
		result.err_msg = C.CString(fmt.Sprintf("failed to obtain client: %v", err))
		return result
	}

	// ---- build http.Request ------------------------------------------------

	method := C.GoString(opts.method)
	urlStr := C.GoString(opts.url)

	var bodyReader io.Reader
	bodyLen := int(opts.body_len)
	if bodyLen > 0 && opts.body != nil {
		// Zero-copy: the []byte points directly into Python-kept-alive C memory.
		bodyData := unsafe.Slice((*byte)(unsafe.Pointer(opts.body)), bodyLen)
		bodyReader = bytes.NewReader(bodyData)
	}

	req, err := http.NewRequest(method, urlStr, bodyReader)
	if err != nil {
		result.err_msg = C.CString(fmt.Sprintf("failed to create request: %v", err))
		return result
	}

	// Override the Host header if explicitly provided (e.g. for sending
	// requests through a proxy while spoofing a different Host).
	if hostOverride := C.GoString(opts.request_host_override); hostOverride != "" {
		req.Host = hostOverride
	}

	// ---- headers -----------------------------------------------------------

	headersLen := int(opts.headers_len)
	if headersLen > 0 && opts.headers != nil {
		headers := http.Header{}

		headerSlice := unsafe.Slice(opts.headers, headersLen)
		for i := 0; i < headersLen; i++ {
			key := C.GoString(headerSlice[i].key)
			value := C.GoString(headerSlice[i].value)
			headers[key] = []string{value}
		}

		orderLen := int(opts.header_order_len)
		if orderLen > 0 && opts.header_order != nil {
			orderSlice := unsafe.Slice(opts.header_order, orderLen)
			var order []string
			for i := 0; i < orderLen; i++ {
				order = append(order, C.GoString(orderSlice[i]))
			}
			headers[http.HeaderOrderKey] = order
		}

		req.Header = headers
	}

	// Pseudo-header order is applied at transport creation time via the
	// client profile (see buildClient).  No per‑request work needed here.

	// ---- request cookies ---------------------------------------------------

	// Attach per-request cookies directly to the request rather than
	// injecting them into the shared client CookieJar (which would cause
	// jar bloat and data races across concurrent requests).
	if cookiesLen := int(opts.request_cookies_len); cookiesLen > 0 && opts.request_cookies != nil {
		cookieSlice := unsafe.Slice(opts.request_cookies, cookiesLen)
		for i := 0; i < cookiesLen; i++ {
			req.AddCookie(&http.Cookie{
				Name:  C.GoString(cookieSlice[i].key),
				Value: C.GoString(cookieSlice[i].value),
			})
		}
	}

	// ---- execute -----------------------------------------------------------

	resp, reqErr := client.Do(req)
	if reqErr != nil {
		result.err_msg = C.CString(fmt.Sprintf("request failed: %v", reqErr))
		return result
	}
	defer resp.Body.Close()

	// ---- read response body -----------------------------------------------

	// Auto-decompress gzip/deflate/brotli encoded bodies (matches existing
	// cffi_src behaviour).  Raw bytes are still returned — the Python side
	// receives the decompressed payload.
	// Skip manual decompression when DisableCompression is requested.
	if int(opts.disable_compression) == 0 && !resp.Uncompressed {
		ce := resp.Header.Get("Content-Encoding")
		resp.Body = http.DecompressBodyByType(resp.Body, ce)
	}

	// Guard against NULL pointer from Python's ffi.NULL (cffi → C boundary).
	var streamPath string
	if opts.stream_output_path != nil {
		streamPath = C.GoString(opts.stream_output_path)
	}
	var respBody []byte
	var readErr error
	var bodyDirectToC bool

	if streamPath != "" {
		// ---- streaming mode: write chunks to disk ------------------------
		respBody, readErr = readBodyStreamToFile(resp.Body, opts)
		// Body is empty when streaming — data went to the file.
	} else if cBody, cLen, cErr := readBodyToCHeap(resp.Body, resp.ContentLength); cBody != nil {
		// Fast path: body read directly into C heap — no Go intermediate.
		result.body = cBody
		result.body_len = C.int(cLen)
		bodyDirectToC = true
	} else if cErr != nil {
		result.err_msg = C.CString(fmt.Sprintf("failed to read response body: %v", cErr))
		return result
	} else {
		respBody, readErr = readAllPooled(resp.Body)
	}
	if !bodyDirectToC {
		if readErr != nil {
			result.err_msg = C.CString(fmt.Sprintf("failed to read response body: %v", readErr))
			return result
		}
		result.body_len = C.int(len(respBody))
		if len(respBody) > 0 {
			cBody := C.malloc(C.size_t(len(respBody)))
			if cBody == nil {
				result.err_msg = C.CString("failed to allocate memory for response body")
				return result
			}
			cSlice := unsafe.Slice((*byte)(cBody), len(respBody))
			copy(cSlice, respBody)
			result.body = (*C.char)(cBody)
		}
	}

	// ---- populate C result ------------------------------------------------

	result.status_code = C.int(resp.StatusCode)

	// Final URL after redirects
	if resp.Request != nil && resp.Request.URL != nil {
		result.target_url = C.CString(resp.Request.URL.String())
	}

	// HTTP protocol version used
	result.used_protocol = C.CString(resp.Proto)

	// ---- response headers + cookies (arena-based, single C allocation) -----
	packResponseArena(result, resp.Header, resp.Cookies())
	if result.err_msg != nil {
		return result
	}

	return result
}

//export FreeResponse
func FreeResponse(res *C.ResponseResult) {
	if res == nil {
		return
	}
	// Free response headers + cookies (arena-based if _resp_strings is set).
	if res._resp_strings != nil {
		// All key/value strings were allocated in a single arena.
		C.free(unsafe.Pointer(res._resp_strings))
		res._resp_strings = nil
		// Headers and cookies share a single combined HttpHeader array.
		if res.response_headers != nil {
			C.free(unsafe.Pointer(res.response_headers))
			res.response_headers = nil
			res.cookies = nil // same allocation, already freed
		}
	} else {
		// Legacy path: individually allocated C.CString strings.
		if res.response_headers != nil && res.response_headers_len > 0 {
			headerSlice := unsafe.Slice(res.response_headers, res.response_headers_len)
			for i := 0; i < int(res.response_headers_len); i++ {
				if headerSlice[i].key != nil {
					C.free(unsafe.Pointer(headerSlice[i].key))
				}
				if headerSlice[i].value != nil {
					C.free(unsafe.Pointer(headerSlice[i].value))
				}
			}
			C.free(unsafe.Pointer(res.response_headers))
			res.response_headers = nil
		}
		if res.cookies != nil && res.cookies_len > 0 {
			cookieSlice := unsafe.Slice(res.cookies, res.cookies_len)
			for i := 0; i < int(res.cookies_len); i++ {
				if cookieSlice[i].key != nil {
					C.free(unsafe.Pointer(cookieSlice[i].key))
				}
				if cookieSlice[i].value != nil {
					C.free(unsafe.Pointer(cookieSlice[i].value))
				}
			}
			C.free(unsafe.Pointer(res.cookies))
			res.cookies = nil
		}
	}
	if res.body != nil {
		C.free(unsafe.Pointer(res.body))
		res.body = nil
	}
	if res.err_msg != nil {
		C.free(unsafe.Pointer(res.err_msg))
		res.err_msg = nil
	}
	if res.target_url != nil {
		C.free(unsafe.Pointer(res.target_url))
		res.target_url = nil
	}
	if res.used_protocol != nil {
		C.free(unsafe.Pointer(res.used_protocol))
		res.used_protocol = nil
	}
	C.free(unsafe.Pointer(res))
}

//export ClearClientPool
func ClearClientPool() {
	clientPoolMu.Lock()
	defer clientPoolMu.Unlock()

	clientPool.Range(func(key, value any) bool {
		if entry, ok := value.(*poolEntry); ok {
			entry.client.CloseIdleConnections()
		} else if client, ok := value.(tls_client.HttpClient); ok {
			// Legacy cleanup: entries stored before poolEntry wrapper was introduced
			client.CloseIdleConnections()
		}
		clientPool.Delete(key)
		return true
	})
	// Note: the eviction goroutine is intentionally NOT stopped here.
	// It continues to run (harmlessly iterating an empty pool until it
	// repopulates) so that TTL eviction remains active across clear cycles.
}

//export GetPoolStats
func GetPoolStats(stats *C.PoolStats) {
	if stats == nil {
		return
	}
	stats.total_evictions = C.longlong(totalEvictions.Load())
	stats.last_eviction_count = C.longlong(lastEvictionCount.Load())
	stats.last_eviction_time = C.longlong(lastEvictionTime.Load())

	// Count current pool entries (approximate — no lock).
	var count int64
	clientPool.Range(func(_, _ any) bool {
		count++
		return true
	})
	stats.pool_entry_count = C.longlong(count)
	stats.pool_ttl_seconds = C.longlong(time.Duration(poolTTLNs.Load()) / time.Second)
	stats.pool_scan_interval_seconds = C.longlong(time.Duration(poolScanIntervalNs.Load()) / time.Second)
}

//export SetPoolTTL
func SetPoolTTL(seconds C.int) {
	if seconds <= 0 {
		seconds = 300 // default 5 minutes
	}
	poolTTLNs.Store(int64(time.Duration(seconds) * time.Second))
}

//export SetPoolScanInterval
func SetPoolScanInterval(seconds C.int) {
	if seconds <= 0 {
		seconds = 60 // default 1 minute
	}
	poolScanIntervalNs.Store(int64(time.Duration(seconds) * time.Second))
}

//export RequestAsync
func RequestAsync(opts *C.RequestOptions, requestID C.uintptr_t, cb unsafe.Pointer) C.int {
	if opts == nil || cb == nil {
		return -1
	}

	// Panic recovery — any panic during deep copy must be converted to
	// an error callback rather than crashing the Python process.
	defer func() {
		if r := recover(); r != nil {
			result := (*C.ResponseResult)(C.malloc(C.size_t(unsafe.Sizeof(C.ResponseResult{}))))
			if result != nil {
				*result = C.ResponseResult{}
				result.err_msg = C.CString(fmt.Sprintf("go panic in RequestAsync: %v", r))
				result.status_code = 0
			}
			C.invoke_async_callback(cb, requestID, result)
		}
	}()

	// Step 1-2: Deep-copy all C data into Go heap immediately, on the calling thread.
	// Python may free the original opts right after this function returns.
	cfg := deepCopyRequestOptions(opts)

	// Step 3-4: Dispatch a goroutine to execute the HTTP request.
	// The goroutine owns cfg and must clean up customTLSClient when done.
	// Every goroutine MUST have a top-level defer/recover to prevent
	// any panic from crashing the Python process (Constraint 3).
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Attempt to send a panic error via the callback.
				// If the callback itself panics, we have no recovery
				// options — the process will crash.
				res := (*C.ResponseResult)(C.malloc(C.size_t(unsafe.Sizeof(C.ResponseResult{}))))
				if res != nil {
					*res = C.ResponseResult{}
					res.err_msg = C.CString(fmt.Sprintf("go panic in async goroutine: %v", r))
					res.status_code = 0
				}
				C.invoke_async_callback(cb, requestID, res)
			}

		// Clean up custom TLS client memory regardless of panic.
		// cfg may be nil if deepCopyRequestOptions panicked — guard against that.
		if cfg != nil && cfg.customTLSClient != nil {
				freeCustomTLSClient(cfg.customTLSClient)
			}
		}()

		result := executeRequestFromConfig(cfg)

		// Step 5-6: Invoke the C callback with the result.
		// CFFI callbacks internally call PyGILState_Ensure to acquire the GIL
		// before entering Python, so this is safe from any goroutine/OS thread.
		if result == nil {
			// Allocate an error result if malloc failed
			result = (*C.ResponseResult)(C.malloc(C.size_t(unsafe.Sizeof(C.ResponseResult{}))))
			if result != nil {
				*result = C.ResponseResult{}
				result.err_msg = C.CString("async request: internal allocation failure")
				result.status_code = 0
			}
		}
		C.invoke_async_callback(cb, requestID, result)
	}()

	return 0
}

func main() {}
