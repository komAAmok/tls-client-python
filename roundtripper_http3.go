//go:build !tls_lite

package tls_client

import (
	"fmt"
	"net/url"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/quic-go-utls/http3"
	tls "github.com/bogdanfinn/utls"
)

// nextProtoH3 mirrors http3.NextProtoH3 so the ALPN switch in
// roundtripper.go stays identical in both build variants.
const nextProtoH3 = http3.NextProtoH3

// buildVariant is reported to bindings via GetBuildVariant().
const BuildVariant = "full"

func buildHTTP3Transport(cfg *http3Config) (http.RoundTripper, error) {
	utlsConfig := &tls.Config{
		ClientSessionCache: cfg.clientSessionCache,
		InsecureSkipVerify: cfg.insecureSkipVerify,
		OmitEmptyPsk:       true,
	}
	if cfg.transportOptions != nil {
		utlsConfig.RootCAs = cfg.transportOptions.RootCAs
		utlsConfig.Certificates = cfg.transportOptions.Certificates
	}

	if cfg.serverNameOverwrite != "" {
		utlsConfig.ServerName = cfg.serverNameOverwrite
	}

	t3 := &http3.Transport{
		TLSClientConfig: utlsConfig,
		EnableDatagrams: true, // Chrome enables H3_DATAGRAM (setting 0x33)
	}

	if cfg.proxyURL != "" {
		parsedURL, parseErr := url.Parse(cfg.proxyURL)
		if parseErr != nil {
			return nil, fmt.Errorf("can not use proxy for HTTP/3: invalid proxy url: %w", parseErr)
		}

		// Only SOCKS5 can tunnel UDP (via UDP ASSOCIATE), which QUIC requires. Every other
		// scheme would leave the QUIC connection unproxied and leak the real IP, so refuse
		// here instead of silently dialing direct.
		if parsedURL.Scheme != "socks5" && parsedURL.Scheme != "socks5h" {
			return nil, fmt.Errorf("can not use proxy for HTTP/3: proxy scheme %q only supports TCP and can not tunnel QUIC/UDP traffic. Use a socks5:// proxy or disable HTTP/3", parsedURL.Scheme)
		}

		t3.Dial = newSOCKS5QUICDialer(cfg.proxyURL)
	}

	http3Settings := cfg.http3Settings

	if http3Settings != nil {
		settingsCopy := make(map[uint64]uint64, len(http3Settings))
		for k, v := range http3Settings {
			settingsCopy[k] = v
		}
		http3Settings = settingsCopy
	}

	// Add random GREASE setting only for browsers that send it (Chrome)
	// Firefox sends GREASE frames but not random GREASE settings
	// Use priority parameter as identification: Chrome has it, Firefox doesn't
	if cfg.http3PriorityParam > 0 {
		greaseID := generateGREASESettingID()
		greaseValue := generateGREASESettingValue()

		if http3Settings == nil {
			http3Settings = make(map[uint64]uint64)
		}
		http3Settings[greaseID] = greaseValue

		// Set the order if available, and append GREASE at the end
		if len(cfg.http3SettingsOrder) > 0 {
			orderWithGrease := make([]uint64, len(cfg.http3SettingsOrder)+1)
			copy(orderWithGrease, cfg.http3SettingsOrder)
			orderWithGrease[len(cfg.http3SettingsOrder)] = greaseID
			t3.AdditionalSettingsOrder = orderWithGrease
		}
	} else {
		// Just use the settings order as-is without random GREASE
		if len(cfg.http3SettingsOrder) > 0 {
			t3.AdditionalSettingsOrder = cfg.http3SettingsOrder
		}
	}

	t3.AdditionalSettings = http3Settings

	if len(cfg.http3PseudoHeaderOrder) > 0 {
		t3.PseudoHeaderOrder = cfg.http3PseudoHeaderOrder
	}

	// Enable GREASE frames based on profile (Chrome sends GREASE frames, Firefox doesn't)
	t3.SendGreaseFrames = cfg.http3SendGreaseFrames

	t3.PriorityParam = cfg.http3PriorityParam

	if cfg.transportOptions != nil {
		t3.DisableCompression = cfg.transportOptions.DisableCompression

		maxResponseHeaderBytes, convErr := Int64ToInt(cfg.transportOptions.MaxResponseHeaderBytes)
		if convErr != nil {
			return nil, fmt.Errorf("error converting MaxResponseHeaderBytes to int: %w", convErr)
		}

		if maxResponseHeaderBytes > 0 {
			t3.MaxResponseHeaderBytes = maxResponseHeaderBytes
		} else if maxResponseHeaderBytes < 0 {
			// -1 means don't send SETTINGS_MAX_FIELD_SECTION_SIZE (Firefox behavior)
			t3.MaxResponseHeaderBytes = -1
		} else {
			t3.MaxResponseHeaderBytes = profileDefaultMaxResponseHeaderBytes(cfg)
		}
	} else {
		t3.MaxResponseHeaderBytes = profileDefaultMaxResponseHeaderBytes(cfg)
	}

	return t3, nil
}

func profileDefaultMaxResponseHeaderBytes(cfg *http3Config) int {
	if cfg.http3PriorityParam > 0 {
		return CHROME_MAX_FIELD_SECTION_SIZE
	}
	return -1
}

