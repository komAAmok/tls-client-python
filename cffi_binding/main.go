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
} ResponseResult;

typedef void (*async_callback_fn)(uintptr_t request_id, ResponseResult* response);
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
// ---------------------------------------------------------------------------

var (
	clientPool   sync.Map
	clientPoolMu sync.Mutex
)

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
	customTLSClient          *C.CustomTlsClient // deep-copied to C heap; freed after use
}

// deepCopyRequestOptions converts a C RequestOptions pointer into a
// goroutine-safe requestConfig.  All C strings and byte arrays are copied
// into Go-managed memory.  The caller (RequestAsync) may free the original
// C opts immediately after this function returns.
func deepCopyRequestOptions(opts *C.RequestOptions) *requestConfig {
	cfg := &requestConfig{
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

	// Body
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
	}

	// CustomTlsClient — deep-copy to C heap so buildCustomProfileFromC can use it.
	// The goroutine frees this copy when done.
	if opts.custom_tls_client != nil {
		cfg.customTLSClient = deepCopyCustomTLSClient(opts.custom_tls_client)
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
	fmt.Fprintf(h, "%s|%s|%s|%s|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d",
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
	// Default/connect headers affect client behaviour
	dhLen := int(opts.default_headers_len)
	if dhLen > 0 && opts.default_headers != nil {
		dhSlice := unsafe.Slice(opts.default_headers, dhLen)
		for i := 0; i < dhLen; i++ {
			fmt.Fprintf(h, "~dh:%s=%s", C.GoString(dhSlice[i].key), C.GoString(dhSlice[i].value))
		}
	}
	chLen := int(opts.connect_headers_len)
	if chLen > 0 && opts.connect_headers != nil {
		chSlice := unsafe.Slice(opts.connect_headers, chLen)
		for i := 0; i < chLen; i++ {
			fmt.Fprintf(h, "~ch:%s=%s", C.GoString(chSlice[i].key), C.GoString(chSlice[i].value))
		}
	}
	// Certificate pinning – host:pin1,pin2 per entry
	cpLen := int(opts.certificate_pinning_hosts_len)
	if cpLen > 0 && opts.certificate_pinning_hosts != nil {
		cpSlice := unsafe.Slice(opts.certificate_pinning_hosts, cpLen)
		for i := 0; i < cpLen; i++ {
			fmt.Fprintf(h, "^cp:%s=", C.GoString(cpSlice[i].host))
			pinLen := int(cpSlice[i].pins_len)
			if pinLen > 0 && cpSlice[i].pins != nil {
				pinSlice := unsafe.Slice(cpSlice[i].pins, pinLen)
				for j := 0; j < pinLen; j++ {
					fmt.Fprintf(h, "%s,", C.GoString(pinSlice[j]))
				}
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
		// H2 settings key-value
		if h2l := int(ctc.h2_settings_len); h2l > 0 {
			for i := 0; i < h2l; i++ {
				if ctc.h2_settings_keys != nil && ctc.h2_settings_values != nil {
					sl := unsafe.Slice(ctc.h2_settings_keys, h2l)
					vl := unsafe.Slice(ctc.h2_settings_values, h2l)
					fmt.Fprintf(h, "|h2s:%s=%d", C.GoString(sl[i]), vl[i])
				}
			}
		}
		// H3 settings key-value
		if h3l := int(ctc.h3_settings_len); h3l > 0 {
			for i := 0; i < h3l; i++ {
				if ctc.h3_settings_keys != nil && ctc.h3_settings_values != nil {
					sl := unsafe.Slice(ctc.h3_settings_keys, h3l)
					vl := unsafe.Slice(ctc.h3_settings_values, h3l)
					fmt.Fprintf(h, "|h3s:%s=%d", C.GoString(sl[i]), vl[i])
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
		// ECH cipher suites
		if ecl := int(ctc.ech_candidate_cipher_suites_len); ecl > 0 && ctc.ech_candidate_cipher_suites != nil {
			ecSlice := unsafe.Slice(ctc.ech_candidate_cipher_suites, ecl)
			for i := 0; i < ecl; i++ {
				fmt.Fprintf(h, "|echcs:%s,%s", C.GoString(ecSlice[i].kdfId), C.GoString(ecSlice[i].aeadId))
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

func getOrCreateClient(opts *C.RequestOptions) (tls_client.HttpClient, error) {
	key := buildCacheKey(opts)

	if client, ok := clientPool.Load(key); ok {
		return client.(tls_client.HttpClient), nil
	}

	// Serialise construction so we never build two identical clients.
	clientPoolMu.Lock()
	defer clientPoolMu.Unlock()

	// Double-check after acquiring the lock.
	if client, ok := clientPool.Load(key); ok {
		return client.(tls_client.HttpClient), nil
	}

	client, err := buildClient(opts)
	if err != nil {
		return nil, err
	}

	clientPool.Store(key, client)
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
	if idleSec := int(opts.idle_conn_timeout_seconds); idleSec > 0 {
		d := time.Duration(idleSec) * time.Second
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
	fmt.Fprintf(h, "%s|%s|%s|%s|%t|%t|%t|%t|%d|%d|%d|%d|%d|%d|%d|%t|%t|%t|%t|%t|%t|%t|%t|%t",
		cfg.clientIdentifier, cfg.proxy, cfg.serverNameOverwrite, cfg.localAddress,
		cfg.insecureSkipVerify, cfg.forceHttp1, cfg.withRandomTLSExtOrder, cfg.withProtocolRacing,
		cfg.maxIdleConns, cfg.maxIdleConnsPerHost, cfg.maxConnsPerHost,
		cfg.maxResponseHeaderBytes, cfg.writeBufferSize, cfg.readBufferSize,
		cfg.idleConnTimeoutSeconds, cfg.disableKeepAlives, cfg.disableCompression,
		cfg.disableHTTP3, cfg.disableIPv4, cfg.disableIPv6, cfg.followRedirects,
		cfg.withoutCookieJar, cfg.allowEmptyCookies, cfg.withDefaultBadPinHandler,
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
	for _, cert := range cfg.clientCertificates {
		fmt.Fprintf(h, "|cc:%x", sha256.Sum256(cert.Certificate[0]))
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
			for i := 0; i < h2l; i++ {
				if ctc.h2_settings_keys != nil && ctc.h2_settings_values != nil {
					sl := unsafe.Slice(ctc.h2_settings_keys, h2l)
					vl := unsafe.Slice(ctc.h2_settings_values, h2l)
					fmt.Fprintf(h, "|h2s:%s=%d", C.GoString(sl[i]), vl[i])
				}
			}
		}
		if h3l := int(ctc.h3_settings_len); h3l > 0 {
			for i := 0; i < h3l; i++ {
				if ctc.h3_settings_keys != nil && ctc.h3_settings_values != nil {
					sl := unsafe.Slice(ctc.h3_settings_keys, h3l)
					vl := unsafe.Slice(ctc.h3_settings_values, h3l)
					fmt.Fprintf(h, "|h3s:%s=%d", C.GoString(sl[i]), vl[i])
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
			for i := 0; i < ecl; i++ {
				fmt.Fprintf(h, "|echcs:%s,%s", C.GoString(ecSlice[i].kdfId), C.GoString(ecSlice[i].aeadId))
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
	key := buildCacheKeyFromConfig(cfg)
	if client, ok := clientPool.Load(key); ok {
		return client.(tls_client.HttpClient), nil
	}
	clientPoolMu.Lock()
	defer clientPoolMu.Unlock()
	if client, ok := clientPool.Load(key); ok {
		return client.(tls_client.HttpClient), nil
	}
	client, err := buildClientFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	clientPool.Store(key, client)
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
	if cfg.idleConnTimeoutSeconds > 0 {
		d := time.Duration(cfg.idleConnTimeoutSeconds) * time.Second
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

	if len(cfg.requestCookies) > 0 {
		client.SetCookies(req.URL, cfg.requestCookies)
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
	if cfg.streamOutputPath != "" {
		respBody, readErr = readBodyStreamToFileFromConfig(resp.Body, cfg)
	} else {
		respBody, readErr = io.ReadAll(resp.Body)
	}
	if readErr != nil {
		result.err_msg = C.CString(fmt.Sprintf("failed to read response body: %v", readErr))
		return result
	}

	result.status_code = C.int(resp.StatusCode)
	result.body_len = C.int(len(respBody))

	if resp.Request != nil && resp.Request.URL != nil {
		result.target_url = C.CString(resp.Request.URL.String())
	}
	result.used_protocol = C.CString(resp.Proto)

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

	if len(resp.Header) > 0 {
		totalEntries := 0
		for _, values := range resp.Header {
			totalEntries += len(values)
		}
		if totalEntries > 0 {
			headerArr := (*C.HttpHeader)(C.malloc(C.size_t(totalEntries) * C.size_t(unsafe.Sizeof(C.HttpHeader{}))))
			if headerArr == nil {
				result.err_msg = C.CString("failed to allocate memory for response headers")
				return result
			}
			result.response_headers = headerArr
			result.response_headers_len = C.int(totalEntries)
			headerSlice := unsafe.Slice(headerArr, totalEntries)
			idx := 0
			for key, values := range resp.Header {
				for _, val := range values {
					ck := C.CString(key)
					cv := C.CString(val)
					headerSlice[idx].key = ck
					headerSlice[idx].value = cv
					idx++
				}
			}
		}
	}

	if responseCookies := resp.Cookies(); len(responseCookies) > 0 {
		n := len(responseCookies)
		cookieArr := (*C.HttpHeader)(C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(C.HttpHeader{}))))
		if cookieArr == nil {
			result.err_msg = C.CString("failed to allocate memory for response cookies")
			return result
		}
		result.cookies = cookieArr
		result.cookies_len = C.int(n)
		cookieSlice := unsafe.Slice(cookieArr, n)
		for i, c := range responseCookies {
			cookieSlice[i].key = C.CString(c.Name)
			cookieSlice[i].value = C.CString(c.Value)
		}
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
		bodyData := C.GoBytes(unsafe.Pointer(opts.body), C.int(bodyLen))
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

	// Pre-populate the cookie jar with user-provided cookies before sending.
	// This is per-request data – not part of the client cache key.
	if cookiesLen := int(opts.request_cookies_len); cookiesLen > 0 && opts.request_cookies != nil {
		cookieSlice := unsafe.Slice(opts.request_cookies, cookiesLen)
		httpCookies := make([]*http.Cookie, cookiesLen)
		for i := 0; i < cookiesLen; i++ {
			httpCookies[i] = &http.Cookie{
				Name:  C.GoString(cookieSlice[i].key),
				Value: C.GoString(cookieSlice[i].value),
			}
		}
		client.SetCookies(req.URL, httpCookies)
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

	if streamPath != "" {
		// ---- streaming mode: write chunks to disk ------------------------
		respBody, readErr = readBodyStreamToFile(resp.Body, opts)
		// Body is empty when streaming — data went to the file.
	} else {
		respBody, readErr = io.ReadAll(resp.Body)
	}

	if readErr != nil {
		result.err_msg = C.CString(fmt.Sprintf("failed to read response body: %v", readErr))
		return result
	}

	// ---- populate C result ------------------------------------------------

	result.status_code = C.int(resp.StatusCode)
	result.body_len = C.int(len(respBody))

	// Final URL after redirects
	if resp.Request != nil && resp.Request.URL != nil {
		result.target_url = C.CString(resp.Request.URL.String())
	}

	// HTTP protocol version used
	result.used_protocol = C.CString(resp.Proto)

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

	// ---- response headers ------------------------------------------------

	if len(resp.Header) > 0 {
		// First pass: count total header entries
		totalEntries := 0
		for _, values := range resp.Header {
			totalEntries += len(values)
		}

		if totalEntries > 0 {
			headerArr := (*C.HttpHeader)(C.malloc(C.size_t(totalEntries) * C.size_t(unsafe.Sizeof(C.HttpHeader{}))))
			if headerArr == nil {
				result.err_msg = C.CString("failed to allocate memory for response headers")
				return result
			}
			// Register the pointer immediately so FreeResponse can clean it
			// up if C.CString panics during iteration below.
			result.response_headers = headerArr
			result.response_headers_len = C.int(totalEntries)

			headerSlice := unsafe.Slice(headerArr, totalEntries)
			idx := 0
			for key, values := range resp.Header {
				for _, val := range values {
					ck := C.CString(key)
					cv := C.CString(val)
					headerSlice[idx].key = ck
					headerSlice[idx].value = cv
					idx++
				}
			}
		}
	}

	// ---- response cookies -------------------------------------------------

	if responseCookies := resp.Cookies(); len(responseCookies) > 0 {
		n := len(responseCookies)
		cookieArr := (*C.HttpHeader)(C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(C.HttpHeader{}))))
		if cookieArr == nil {
			result.err_msg = C.CString("failed to allocate memory for response cookies")
			return result
		}
		// Register the pointer immediately so FreeResponse can clean it
		// up if C.CString panics during iteration below.
		result.cookies = cookieArr
		result.cookies_len = C.int(n)

		cookieSlice := unsafe.Slice(cookieArr, n)
		for i, c := range responseCookies {
			cookieSlice[i].key = C.CString(c.Name)
			cookieSlice[i].value = C.CString(c.Value)
		}
	}

	return result
}

//export FreeResponse
func FreeResponse(res *C.ResponseResult) {
	if res == nil {
		return
	}
	// Free response headers (individual key/value strings + array)
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
	// Free response cookies (individual key/value strings + array)
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
	C.free(unsafe.Pointer(res))
}

//export ClearClientPool
func ClearClientPool() {
	clientPoolMu.Lock()
	defer clientPoolMu.Unlock()

	clientPool.Range(func(key, value any) bool {
		if client, ok := value.(tls_client.HttpClient); ok {
			client.CloseIdleConnections()
		}
		clientPool.Delete(key)
		return true
	})
}

//export RequestAsync
func RequestAsync(opts *C.RequestOptions, requestID C.uintptr_t, cb C.async_callback_fn) C.int {
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
			(*cb)(requestID, result)
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
				(*cb)(requestID, res)
			}

			// Clean up custom TLS client memory regardless of panic
			if cfg.customTLSClient != nil {
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
		(*cb)(requestID, result)
	}()

	return 0
}

func main() {}
