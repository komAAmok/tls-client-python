package tls_client

import (
	http "github.com/bogdanfinn/fhttp"
)

// HeaderOrderForDest returns the header order Chrome would use for a given
// Sec-Fetch-Dest value.
//
// Chromium does not send one header order: a top-level navigation orders the
// Client Hints first and ends with `priority` + `cookie`, while a subresource
// request drops the navigation-only headers and moves the `referer` up.  A
// client that always sends the navigation order for every request is
// detectable, which is why the order is selected by destination rather than
// fixed per session.
//
// The returned slice is a copy: callers may set it on http.Header under
// http.HeaderOrderKey without disturbing the shared table.
func HeaderOrderForDest(browser, dest string) []string {
	table := headerOrderTable(browser)
	if table == nil {
		return nil
	}

	order, ok := table[dest]
	if !ok {
		order = table["document"]
	}
	if order == nil {
		return nil
	}

	out := make([]string, len(order))
	copy(out, order)
	return out
}

// ApplyHeaderOrderForDest sets the header order on hdr according to the
// request's Sec-Fetch-Dest value.  It is a no-op when no order is known.
func ApplyHeaderOrderForDest(hdr http.Header, browser, dest string) {
	if hdr == nil {
		return
	}
	order := HeaderOrderForDest(browser, dest)
	if len(order) == 0 {
		return
	}
	hdr[http.HeaderOrderKey] = order
}

// headerOrderTable returns the per-destination order table for a browser.
func headerOrderTable(browser string) map[string][]string {
	switch browser {
	case "chrome", "brave", "opera":
		return chromeHeaderOrderByDest
	case "firefox":
		return firefoxHeaderOrderByDest
	case "safari":
		return safariHeaderOrderByDest
	}
	return nil
}

// chromeHeaderOrderByDest holds the captured header order per destination.
// Keys are Sec-Fetch-Dest values.
var chromeHeaderOrderByDest = map[string][]string{
	// Top-level navigation.
	"document": {
		"sec-ch-ua",
		"sec-ch-ua-mobile",
		"sec-ch-ua-platform",
		"upgrade-insecure-requests",
		"user-agent",
		"accept",
		"sec-fetch-site",
		"sec-fetch-mode",
		"sec-fetch-user",
		"sec-fetch-dest",
		"accept-encoding",
		"accept-language",
		"priority",
		"cookie",
	},
	// XHR / fetch.
	"empty": {
		"sec-ch-ua",
		"sec-ch-ua-mobile",
		"sec-ch-ua-platform",
		"user-agent",
		"accept",
		"sec-fetch-site",
		"sec-fetch-mode",
		"sec-fetch-dest",
		"referer",
		"accept-encoding",
		"accept-language",
		"priority",
		"cookie",
	},
	// Script / stylesheet / image / font subresources.
	"script":    subresourceOrder,
	"style":     subresourceOrder,
	"image":     subresourceOrder,
	"font":      subresourceOrder,
	"audio":     subresourceOrder,
	"video":     subresourceOrder,
	"track":     subresourceOrder,
	"iframe":    {"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer", "accept-encoding", "accept-language"},
	"frame":     {"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer", "accept-encoding", "accept-language"},
	"worker":    subresourceOrder,
	"manifest":  subresourceOrder,
	"websocket": {"user-agent", "accept-language", "cache-control", "connection", "upgrade", "origin", "sec-websocket-key", "sec-websocket-version", "sec-websocket-extensions", "accept-encoding"},
	"prefetch":  subresourceOrder,
	"xslt":      subresourceOrder,
	"embed":     subresourceOrder,
	"object":    subresourceOrder,
	"report":    {"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "user-agent", "content-type", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "accept-encoding", "accept-language"},
}

// subresourceOrder is the shared Chrome order for most non-navigation
// subresources: no navigation-only headers, referer before encoding/language.
var subresourceOrder = []string{
	"sec-ch-ua",
	"sec-ch-ua-mobile",
	"sec-ch-ua-platform",
	"user-agent",
	"accept",
	"sec-fetch-site",
	"sec-fetch-mode",
	"sec-fetch-dest",
	"referer",
	"accept-encoding",
	"accept-language",
	"priority",
	"cookie",
}

// firefoxHeaderOrderByDest — Firefox sends no Client Hints and uses `te`
// instead of `priority`.
var firefoxHeaderOrderByDest = map[string][]string{
	"document": {
		"host",
		"user-agent",
		"accept",
		"accept-language",
		"accept-encoding",
		"upgrade-insecure-requests",
		"sec-fetch-dest",
		"sec-fetch-mode",
		"sec-fetch-site",
		"sec-fetch-user",
		"te",
		"cookie",
	},
	"empty": {
		"host",
		"user-agent",
		"accept",
		"accept-language",
		"accept-encoding",
		"sec-fetch-dest",
		"sec-fetch-mode",
		"sec-fetch-site",
		"referer",
		"te",
		"cookie",
	},
	"script":   firefoxSubresource,
	"style":    firefoxSubresource,
	"image":    firefoxSubresource,
	"font":     firefoxSubresource,
	"audio":    firefoxSubresource,
	"video":    firefoxSubresource,
	"iframe":   firefoxSubresource,
	"worker":   firefoxSubresource,
	"track":    firefoxSubresource,
	"embed":    firefoxSubresource,
	"object":   firefoxSubresource,
	"report":   firefoxSubresource,
	"prefetch": firefoxSubresource,
	"manifest": firefoxSubresource,
}

var firefoxSubresource = []string{
	"host",
	"user-agent",
	"accept",
	"accept-language",
	"accept-encoding",
	"sec-fetch-dest",
	"sec-fetch-mode",
	"sec-fetch-site",
	"referer",
	"te",
	"cookie",
}

// safariHeaderOrderByDest — Safari also omits Client Hints on older versions
// and orders `accept` first for navigations.
var safariHeaderOrderByDest = map[string][]string{
	"document": {
		"accept",
		"sec-fetch-site",
		"sec-fetch-mode",
		"sec-fetch-dest",
		"user-agent",
		"accept-language",
		"accept-encoding",
		"referer",
		"cookie",
	},
	"empty": {
		"accept",
		"sec-fetch-site",
		"user-agent",
		"accept-language",
		"accept-encoding",
		"referer",
		"sec-fetch-mode",
		"sec-fetch-dest",
		"cookie",
	},
	"script": safariSubresource,
	"style":  safariSubresource,
	"image":  safariSubresource,
	"font":   safariSubresource,
	"audio":  safariSubresource,
	"video":  safariSubresource,
	"iframe": safariSubresource,
	"worker": safariSubresource,
	"track":  safariSubresource,
}

var safariSubresource = []string{
	"accept",
	"sec-fetch-site",
	"user-agent",
	"accept-language",
	"accept-encoding",
	"referer",
	"sec-fetch-mode",
	"sec-fetch-dest",
	"cookie",
}
