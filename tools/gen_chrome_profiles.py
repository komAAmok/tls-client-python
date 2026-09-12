#!/usr/bin/env python3
"""Generate ``profiles/chrome_captured_profiles.go`` from real captures.

Reads ``tools/_chrome_captures.json`` (see ``extract_chrome_captures.py``) and
emits Go source defining one ``ClientProfile`` per captured Chrome major
version.  The profiles build their ClientHello from the *real* per-version TLS
extension order recorded in the capture, which is what makes the JA3/JA4 the
engine produces match the browser byte-for-byte.

    python tools/gen_chrome_profiles.py            # write the Go file
    python tools/gen_chrome_profiles.py --check    # fail if it is stale

The generated file is committed.  ``--check`` regenerates in memory and
compares against the on-disk file, so CI catches capture drift.
"""

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CAPTURES = os.path.join(ROOT, "tools", "_chrome_captures.json")
DEFAULT_OUT = os.path.join(ROOT, "profiles", "chrome_captured_profiles.go")

CIPHER_GO = {
    0x1301: "tls.TLS_AES_128_GCM_SHA256",
    0x1302: "tls.TLS_AES_256_GCM_SHA384",
    0x1303: "tls.TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02F: "tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC030: "tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA9: "tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA8: "tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xC009: "tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC013: "tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC00A: "tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC014: "tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0x009C: "tls.TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "tls.TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "tls.TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "tls.TLS_RSA_WITH_AES_256_CBC_SHA",
}

CURVE_GO = {
    0x001D: "tls.X25519",
    0x0017: "tls.CurveP256",
    0x0018: "tls.CurveP384",
    0x0019: "tls.CurveP521",
    0x11EC: "tls.X25519MLKEM768",
    0x6399: "tls.X25519Kyber768Draft00",
}

SIGALG_GO = {
    0x0403: "tls.ECDSAWithP256AndSHA256",
    0x0804: "tls.PSSWithSHA256",
    0x0401: "tls.PKCS1WithSHA256",
    0x0503: "tls.ECDSAWithP384AndSHA384",
    0x0805: "tls.PSSWithSHA384",
    0x0501: "tls.PKCS1WithSHA384",
    0x0806: "tls.PSSWithSHA512",
    0x0601: "tls.PKCS1WithSHA512",
    0x0603: "tls.ECDSAWithP521AndSHA512",
    0x0203: "tls.ECDSAWithSHA1",
    0x0201: "tls.PKCS1WithSHA1",
    0x0807: "tls.Ed25519",
    0x0904: "tls.SignatureScheme(0x0904)",
    0x0905: "tls.SignatureScheme(0x0905)",
    0x0906: "tls.SignatureScheme(0x0906)",
}

# Name -> codepoint for signature_algorithms when tls.peet.ws prints names.
SIGALG_NAME = {
    "ecdsa_secp256r1_sha256": "tls.ECDSAWithP256AndSHA256",
    "rsa_pss_rsae_sha256": "tls.PSSWithSHA256",
    "rsa_pkcs1_sha256": "tls.PKCS1WithSHA256",
    "ecdsa_secp384r1_sha384": "tls.ECDSAWithP384AndSHA384",
    "rsa_pss_rsae_sha384": "tls.PSSWithSHA384",
    "rsa_pkcs1_sha384": "tls.PKCS1WithSHA384",
    "rsa_pss_rsae_sha512": "tls.PSSWithSHA512",
    "rsa_pkcs1_sha512": "tls.PKCS1WithSHA512",
    "ecdsa_secp521r1_sha512": "tls.ECDSAWithP521AndSHA512",
    "rsa_pkcs1_sha1": "tls.PKCS1WithSHA1",
    "ecdsa_sha1": "tls.ECDSAWithSHA1",
    "ed25519": "tls.Ed25519",
}


def cipher_go(v):
    return CIPHER_GO.get(v, "0x%04x" % v)


def curve_go(v):
    return CURVE_GO.get(v, "tls.CurveID(0x%04x)" % v)


def sigalgs_go(algs):
    """Render a signature_algorithms list to Go expressions."""
    out = []
    for a in algs or []:
        if isinstance(a, str):
            if a.startswith("0x"):
                # tls.peet.ws prints GREASE as 0xNNNN; keep utls' placeholder so
                # the engine draws a fresh GREASE value per connection.
                out.append("tls.SignatureScheme(tls.GREASE_PLACEHOLDER)")
            else:
                out.append(SIGALG_NAME.get(a, "tls.SignatureScheme(0x0000) /* %s */" % a))
        else:
            out.append(SIGALG_GO.get(a, "tls.SignatureScheme(0x%04x)" % a))
    return out


def emit(header, caps):
    lines = [header]
    lines.append("package profiles")
    lines.append("")
    lines.append("import (")
    lines.append('\thttp2 "github.com/bogdanfinn/fhttp/http2"')
    lines.append('\ttls "github.com/bogdanfinn/utls"')
    lines.append(")")
    lines.append("")
    lines.append("// chromeCaptured majors are the versions with a recorded capture.")
    lines.append("var chromeCapturedMajors = []int{")
    majors = sorted(int(k) for k in caps)
    lines.append("\t" + ", ".join(str(m) for m in majors) + ",")
    lines.append("}")
    lines.append("")

    # --- per-version ClientHello specs -----------------------------------
    lines.append("// chromeCapturedSpec returns the exact ClientHello spec for a captured")
    lines.append("// Chrome major version.  Extension order follows the wire capture.")
    lines.append("func chromeCapturedSpec(major int) (tls.ClientHelloSpec, error) {")
    lines.append("\tswitch major {")
    for m in majors:
        cap = caps[str(m)]
        lines.append("\tcase %d:" % m)
        lines.append("\t\treturn tls.ClientHelloSpec{")
        # ciphers
        lines.append("\t\t\tCipherSuites: []uint16{")
        for c in cap["cipher_hex"]:
            if c == 0x0A0A or (c & 0x0F0F) == 0x0A0A:
                lines.append("\t\t\t\ttls.GREASE_PLACEHOLDER,")
            else:
                lines.append("\t\t\t\t%s," % cipher_go(c))
        lines.append("\t\t\t},")
        lines.append("\t\t\tCompressionMethods: []uint8{tls.CompressionNone},")
        lines.append("\t\t\tExtensions: []tls.TLSExtension{")
        for eid in cap["ext_ids"]:
            lines.append("\t\t\t\t" + ext_expr(eid, m) + ",")
        lines.append("\t\t\t},")
        lines.append("\t\t}, nil")
    lines.append("\t}")
    lines.append("\treturn tls.ClientHelloSpec{}, errUnknownChromeCapture(major)")
    lines.append("}")
    lines.append("")

    # --- curves helper ----------------------------------------------------
    lines.append("// chromeCapturedCurves returns the supported_groups list for a version.")
    lines.append("func chromeCapturedCurves(major int) []tls.CurveID {")
    lines.append("\tswitch major {")
    for m in majors:
        cap = caps[str(m)]
        items = []
        for c in cap["curve_hex"]:
            if (c & 0x0F0F) == 0x0A0A:
                items.append("tls.GREASE_PLACEHOLDER")
            else:
                items.append(curve_go(c))
        lines.append("\tcase %d:" % m)
        lines.append("\t\treturn []tls.CurveID{" + ", ".join(items) + "}")
    lines.append("\t}")
    lines.append("\treturn nil")
    lines.append("}")
    lines.append("")

    # --- signature algorithms --------------------------------------------
    lines.append("// chromeCapturedSignatureAlgorithms returns the signature_algorithms list.")
    lines.append("func chromeCapturedSignatureAlgorithms(major int) []tls.SignatureScheme {")
    lines.append("\tswitch major {")
    for m in majors:
        cap = caps[str(m)]
        algs = sigalgs_go(cap.get("signature_algorithms"))
        lines.append("\tcase %d:" % m)
        lines.append("\t\treturn []tls.SignatureScheme{" + ", ".join(algs) + "}")
    lines.append("\t}")
    lines.append("\treturn nil")
    lines.append("}")
    lines.append("")

    # --- key shares helper ------------------------------------------------
    lines.append("// chromeCapturedKeyShares returns the key_share entries for a version.")
    lines.append("// The leading GREASE share mirrors Chromium; the PQ share appears once")
    lines.append("// the version advertises X25519MLKEM768 in supported_groups.")
    lines.append("func chromeCapturedKeyShares(major int) []tls.KeyShare {")
    lines.append("\tcurves := chromeCapturedCurves(major)")
    lines.append("\tshares := make([]tls.KeyShare, 0, len(curves))")
    lines.append("\tfor _, c := range curves {")
    lines.append("\t\tswitch c {")
    lines.append("\t\tcase tls.GREASE_PLACEHOLDER:")
    lines.append("\t\t\tshares = append(shares, tls.KeyShare{Group: tls.GREASE_PLACEHOLDER, Data: []byte{0}})")
    lines.append("\t\tcase tls.X25519, tls.X25519MLKEM768, tls.CurveP256:")
    lines.append("\t\t\tshares = append(shares, tls.KeyShare{Group: c})")
    lines.append("\t\t}")
    lines.append("\t}")
    lines.append("\tif len(shares) == 0 {")
    lines.append("\t\tshares = []tls.KeyShare{{Group: tls.X25519}}")
    lines.append("\t}")
    lines.append("\treturn shares")
    lines.append("}")
    lines.append("")

    # --- H2 settings from akamai fingerprint -----------------------------
    lines.append("// chromeCapturedH2Settings returns the SETTINGS map for a version.")
    lines.append("func chromeCapturedH2Settings(major int) map[http2.SettingID]uint32 {")
    lines.append("\tswitch major {")
    for m in majors:
        s = parse_akamai(caps[str(m)]["akamai"])
        entries = []
        for sid, val in s["settings"]:
            entries.append("%s: %d" % (setting_go(sid), val))
        lines.append("\tcase %d:" % m)
        lines.append("\t\treturn map[http2.SettingID]uint32{" + ", ".join(entries) + "}")
    lines.append("\t}")
    lines.append("\treturn nil")
    lines.append("}")
    lines.append("")

    lines.append("// chromeCapturedH2SettingsOrder returns the SETTINGS frame id order.")
    lines.append("func chromeCapturedH2SettingsOrder(major int) []http2.SettingID {")
    lines.append("\tswitch major {")
    for m in majors:
        s = parse_akamai(caps[str(m)]["akamai"])
        items = [setting_go(sid) for sid, _ in s["settings"]]
        lines.append("\tcase %d:" % m)
        lines.append("\t\treturn []http2.SettingID{" + ", ".join(items) + "}")
    lines.append("\t}")
    lines.append("\treturn nil")
    lines.append("}")
    lines.append("")

    lines.append("// chromeCapturedConnectionFlow returns the connection WINDOW_UPDATE.")
    lines.append("func chromeCapturedConnectionFlow(major int) uint32 {")
    lines.append("\tswitch major {")
    for m in majors:
        s = parse_akamai(caps[str(m)]["akamai"])
        lines.append("\tcase %d:" % m)
        lines.append("\t\treturn %d" % s["window_update"])
    lines.append("\t}")
    lines.append("\treturn 15663105")
    lines.append("}")
    lines.append("")

    lines.append("// chromeCapturedPseudoHeaderOrder returns the H2/H3 pseudo-header order.")
    lines.append("func chromeCapturedPseudoHeaderOrder(major int) []string {")
    lines.append('\treturn []string{":method", ":authority", ":scheme", ":path"}')
    lines.append("}")
    lines.append("")

    lines.append("// chromeCapturedH3Settings returns the HTTP/3 SETTINGS for a version.")
    lines.append("func chromeCapturedH3Settings(major int) map[uint64]uint64 {")
    lines.append("\treturn map[uint64]uint64{")
    lines.append("\t\t0x1:  65536,")
    lines.append("\t\t0x6:  262144,")
    lines.append("\t\t0x7:  100,")
    lines.append("\t\t0x33: 1,")
    lines.append("\t}")
    lines.append("}")
    lines.append("")

    lines.append("// chromeCapturedH3SettingsOrder returns the HTTP/3 SETTINGS frame order.")
    lines.append("func chromeCapturedH3SettingsOrder(major int) []uint64 {")
    lines.append("\treturn []uint64{0x1, 0x6, 0x7, 0x33}")
    lines.append("}")
    lines.append("")

    # --- profile constructor registry ------------------------------------
    lines.append("// CapturedChromeProfile builds a ClientProfile for a captured Chrome")
    lines.append("// major version.  ok is false when no capture exists for the version.")
    lines.append("func CapturedChromeProfile(major int) (ClientProfile, bool) {")
    lines.append("\tswitch major {")
    for m in majors:
        lines.append("\tcase %d:" % m)
        lines.append("\t\treturn ClientProfile{")
        lines.append("\t\t\tclientHelloId: tls.ClientHelloID{")
        lines.append('\t\t\t\tClient:               "Chrome",')
        lines.append("\t\t\t\tRandomExtensionOrder: false,")
        lines.append('\t\t\t\tVersion:              "%d",' % m)
        lines.append("\t\t\t\tSeed:                 nil,")
        lines.append("\t\t\t\tSpecFactory: func() (tls.ClientHelloSpec, error) {")
        lines.append("\t\t\t\t\treturn chromeCapturedSpec(%d)" % m)
        lines.append("\t\t\t\t},")
        lines.append("\t\t\t},")
        lines.append("\t\t\tsettings:               chromeCapturedH2Settings(%d)," % m)
        lines.append("\t\t\tsettingsOrder:          chromeCapturedH2SettingsOrder(%d)," % m)
        lines.append("\t\t\tpseudoHeaderOrder:      chromeCapturedPseudoHeaderOrder(%d)," % m)
        lines.append("\t\t\tconnectionFlow:         chromeCapturedConnectionFlow(%d)," % m)
        lines.append("\t\t\thttp3Settings:          chromeCapturedH3Settings(%d)," % m)
        lines.append("\t\t\thttp3SettingsOrder:     chromeCapturedH3SettingsOrder(%d)," % m)
        lines.append("\t\t\thttp3PseudoHeaderOrder: chromeCapturedPseudoHeaderOrder(%d)," % m)
        lines.append("\t\t\thttp3SendGreaseFrames:  true,")
        lines.append("\t\t}, true")
    lines.append("\t}")
    lines.append("\treturn ClientProfile{}, false")
    lines.append("}")
    lines.append("")

    lines.append("// CapturedChromeMajors lists the Chrome major versions with a capture,")
    lines.append("// newest first.  Used by the binding to expose the generated profiles.")
    lines.append("func CapturedChromeMajors() []int {")
    lines.append("\tout := make([]int, len(chromeCapturedMajors))")
    lines.append("\tfor i, m := range chromeCapturedMajors {")
    lines.append("\t\tout[i] = m")
    lines.append("\t}")
    lines.append("\treturn out")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def ext_expr(eid, major):
    """Render one extension entry to a Go expression.

    Data-bearing extensions (curves, signature algorithms, key shares) are
    resolved through per-version helpers so the generated spec carries the
    *captured* contents rather than a shared placeholder.
    """
    if eid == "G":
        return "&tls.UtlsGREASEExtension{}"
    if eid is None:
        return "&tls.GenericExtension{Id: 0}"
    simple = {
        0: "&tls.SNIExtension{}",
        5: "&tls.StatusRequestExtension{}",
        10: "&tls.SupportedCurvesExtension{Curves: chromeCapturedCurves(%d)}" % major,
        11: "&tls.SupportedPointsExtension{SupportedPoints: []byte{tls.PointFormatUncompressed}}",
        13: "&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: chromeCapturedSignatureAlgorithms(%d)}" % major,
        16: '&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}',
        18: "&tls.SCTExtension{}",
        21: "&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle}",
        23: "&tls.ExtendedMasterSecretExtension{}",
        27: "&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli}}",
        28: "&tls.FakeRecordSizeLimitExtension{Limit: 0x4001}",
        35: "&tls.SessionTicketExtension{}",
        43: "&tls.SupportedVersionsExtension{Versions: []uint16{tls.GREASE_PLACEHOLDER, tls.VersionTLS13, tls.VersionTLS12}}",
        45: "&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}}",
        51: "&tls.KeyShareExtension{KeyShares: chromeCapturedKeyShares(%d)}" % major,
        65281: "&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient}",
        65037: "tls.BoringGREASEECH()",
        17513: '&tls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}}',
        17613: '&tls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}}',
    }
    if eid in simple:
        return simple[eid]
    return "&tls.GenericExtension{Id: %d}" % eid


def setting_go(sid):
    names = {
        1: "http2.SettingHeaderTableSize",
        2: "http2.SettingEnablePush",
        3: "http2.SettingMaxConcurrentStreams",
        4: "http2.SettingInitialWindowSize",
        5: "http2.SettingMaxFrameSize",
        6: "http2.SettingMaxHeaderListSize",
    }
    return names.get(sid, "http2.SettingID(0x%x)" % sid)


def parse_akamai(fp):
    """Parse an Akamai H2 fingerprint string into settings + window update."""
    head, window, _prio, _order = fp.split("|")
    settings = []
    for part in head.split(";"):
        sid, val = part.split(":")
        settings.append((int(sid), int(val)))
    return {"settings": settings, "window_update": int(window)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--captures", default=DEFAULT_CAPTURES)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--check", action="store_true")
    ap.add_argument(
        "--majors",
        default="",
        help=(
            "Comma-separated Chrome majors to emit.  Default: all captured "
            "versions.  Used by the size-trimmed (nano) build so the unused "
            "profile data is absent from the binary rather than merely "
            "deleted from the runtime map."
        ),
    )
    args = ap.parse_args()

    with open(args.captures, "r", encoding="utf-8") as handle:
        caps = json.load(handle)

    if args.majors:
        wanted = [m.strip() for m in args.majors.split(",") if m.strip()]
        unknown = [m for m in wanted if m not in caps]
        if unknown:
            print(
                "ERROR: no capture for major(s) %s" % ", ".join(unknown),
                file=sys.stderr,
            )
            return 1
        caps = {m: caps[m] for m in wanted}

    header = ("// Code generated by tools/gen_chrome_profiles.py from real Chrome\n"
              "// 99-153 captures (tools/_chrome_captures.json). DO NOT EDIT.\n"
              "//\n"
              "// Regenerate: python tools/gen_chrome_profiles.py\n")
    text = emit(header, caps)

    if args.check:
        try:
            with open(args.out, "r", encoding="utf-8") as handle:
                current = handle.read()
        except FileNotFoundError:
            print("MISSING: %s" % args.out, file=sys.stderr)
            return 1
        if current != text:
            print("STALE: %s differs from the generator output" % args.out, file=sys.stderr)
            return 1
        print("OK: %s is up to date" % args.out)
        return 0

    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(text)
    majors = sorted(int(k) for k in caps)
    print("wrote %s: %d versions (%d..%d)" % (args.out, len(majors), majors[0], majors[-1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
