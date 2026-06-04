package main

/*
#include <stdlib.h>

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
    CustomTlsClient* custom_tls_client;
} RequestOptions;

typedef struct {
    int   status_code;
    char* body;
    int   body_len;
    char* err_msg;
    HttpHeader* response_headers;
    int   response_headers_len;
} ResponseResult;
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
		return nil, fmt.Errorf("JA3 spec factory: %w", err)
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
				resolvedH2Settings[resolvedKey] = valSlice[i]
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
				resolvedH3Settings[resolvedKey] = valSlice[i]
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
				StreamID: pfSlice[i].streamID,
				PriorityParam: http2.PriorityParam{
					StreamDep: pfSlice[i].priorityParam.streamDep,
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
			StreamDep: ctc.header_priority.streamDep,
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

	// Optional EOF marker
	eof := C.GoString(opts.stream_output_eof_symbol)
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
			msg := fmt.Sprintf("go panic: %v", r)
			result.err_msg = C.CString(msg)
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

	streamPath := C.GoString(opts.stream_output_path)
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

			result.response_headers = headerArr
			result.response_headers_len = C.int(totalEntries)
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

func main() {}
