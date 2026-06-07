package profiles

import (
	"github.com/bogdanfinn/fhttp/http2"
	tls "github.com/bogdanfinn/utls"
)

var DefaultClientProfile = Chrome_146

var MappedTLSClients = map[string]ClientProfile{
	"chrome_103":             Chrome_103,
	"chrome_104":             Chrome_104,
	"chrome_105":             Chrome_105,
	"chrome_106":             Chrome_106,
	"chrome_107":             Chrome_107,
	"chrome_108":             Chrome_108,
	"chrome_109":             Chrome_109,
	"chrome_110":             Chrome_110,
	"chrome_111":             Chrome_111,
	"chrome_112":             Chrome_112,
	"chrome_116_PSK":         Chrome_116_PSK,
	"chrome_116_PSK_PQ":      Chrome_116_PSK_PQ,
	"chrome_117":             Chrome_117,
	"chrome_120":             Chrome_120,
	"chrome_124":             Chrome_124,
	"chrome_130_PSK":         Chrome_130_PSK,
	"chrome_131":             Chrome_131,
	"chrome_131_PSK":         Chrome_131_PSK,
	"chrome_133":             Chrome_133,
	"chrome_133_PSK":         Chrome_133_PSK,
	"chrome_144":             Chrome_144,
	"chrome_144_PSK":         Chrome_144_PSK,
	"chrome_146":             Chrome_146,
	"chrome_146_PSK":         Chrome_146_PSK,
	"brave_146":              Brave_146,
	"brave_146_PSK":          Brave_146_PSK,
	"safari_15_6_1":          Safari_15_6_1,
	"safari_16_0":            Safari_16_0,
	"safari_ipad_15_6":       Safari_Ipad_15_6,
	"safari_ios_15_5":        Safari_IOS_15_5,
	"safari_ios_15_6":        Safari_IOS_15_6,
	"safari_ios_16_0":        Safari_IOS_16_0,
	"safari_ios_17_0":        Safari_IOS_17_0,
	"safari_ios_18_0":        Safari_IOS_18_0,
	"safari_ios_18_5":        Safari_IOS_18_5,
	"safari_ios_26_0":        Safari_IOS_26_0,
	"firefox_102":            Firefox_102,
	"firefox_104":            Firefox_104,
	"firefox_105":            Firefox_105,
	"firefox_106":            Firefox_106,
	"firefox_108":            Firefox_108,
	"firefox_110":            Firefox_110,
	"firefox_117":            Firefox_117,
	"firefox_120":            Firefox_120,
	"firefox_123":            Firefox_123,
	"firefox_132":            Firefox_132,
	"firefox_133":            Firefox_133,
	"firefox_135":            Firefox_135,
	"firefox_146_PSK":        Firefox_146_PSK,
	"firefox_147":            Firefox_147,
	"firefox_147_PSK":        Firefox_147_PSK,
	"firefox_148":            Firefox_148,
	"opera_89":               Opera_89,
	"opera_90":               Opera_90,
	"opera_91":               Opera_91,
	"zalando_android_mobile": ZalandoAndroidMobile,
	"zalando_ios_mobile":     ZalandoIosMobile,
	"nike_ios_mobile":        NikeIosMobile,
	"nike_android_mobile":    NikeAndroidMobile,
	"cloudscraper":           CloudflareCustom,
	"mms_ios":                MMSIos,
	"mms_ios_1":              MMSIos,
	"mms_ios_2":              MMSIos2,
	"mms_ios_3":              MMSIos3,
	"mesh_ios":               MeshIos,
	"mesh_ios_1":             MeshIos,
	"mesh_ios_2":             MeshIos2,
	"mesh_android":           MeshAndroid,
	"mesh_android_1":         MeshAndroid,
	"mesh_android_2":         MeshAndroid2,
	"confirmed_ios":          ConfirmedIos,
	"confirmed_android":      ConfirmedAndroid,
	"okhttp4_android_7":      Okhttp4Android7,
	"okhttp4_android_8":      Okhttp4Android8,
	"okhttp4_android_9":      Okhttp4Android9,
	"okhttp4_android_10":     Okhttp4Android10,
	"okhttp4_android_11":     Okhttp4Android11,
	"okhttp4_android_12":     Okhttp4Android12,
	"okhttp4_android_13":     Okhttp4Android13,
}

type ClientProfile struct {
	clientHelloId          tls.ClientHelloID
	headerPriority         *http2.PriorityParam
	settings               map[http2.SettingID]uint32
	settingsOrder          []http2.SettingID
	priorities             []http2.Priority
	pseudoHeaderOrder      []string
	connectionFlow         uint32
	streamID               uint32
	allowHTTP              bool
	http3Settings          map[uint64]uint64
	http3SettingsOrder     []uint64
	http3PriorityParam     uint32
	http3PseudoHeaderOrder []string
	http3SendGreaseFrames  bool
	tcpFingerprint         *TcpFingerprint // nil = auto-infer from Client name
}

func NewClientProfile(clientHelloId tls.ClientHelloID, settings map[http2.SettingID]uint32, settingsOrder []http2.SettingID, pseudoHeaderOrder []string, connectionFlow uint32, priorities []http2.Priority, headerPriority *http2.PriorityParam, streamID uint32, allowHTTP bool, http3Settings map[uint64]uint64, http3SettingsOrder []uint64, http3PriorityParam uint32, http3PseudoHeaderOrder []string, http3SendGreaseFrames bool) ClientProfile {
	return ClientProfile{
		clientHelloId:          clientHelloId,
		settings:               settings,
		settingsOrder:          settingsOrder,
		pseudoHeaderOrder:      pseudoHeaderOrder,
		connectionFlow:         connectionFlow,
		priorities:             priorities,
		headerPriority:         headerPriority,
		streamID:               streamID,
		allowHTTP:              allowHTTP,
		http3Settings:          http3Settings,
		http3SettingsOrder:     http3SettingsOrder,
		http3PriorityParam:     http3PriorityParam,
		http3PseudoHeaderOrder: http3PseudoHeaderOrder,
		http3SendGreaseFrames:  http3SendGreaseFrames,
	}
}

// TcpFingerprint holds the TCP/IP stack parameters that should be set on outgoing
// connections to mimic a specific operating system.  Each field is a pointer — nil
// means "use the OS default"; a non-nil value forces the corresponding socket option.
type TcpFingerprint struct {
	TTL         *int // IP TTL (Time To Live).  Windows=128, Linux/macOS=64.
	WindowSize  *int // TCP receive window size.  Windows=64240, Linux/macOS=65535.
	WindowScale *int // TCP window scale factor.  Windows=8, Linux=7, macOS=6.
	MSS         *int // TCP MSS (Maximum Segment Size).  Standard Ethernet=1460.
}

// DefaultTcpFingerprints maps client names to their default OS TCP fingerprints.
var DefaultTcpFingerprints = map[string]TcpFingerprint{
	"Windows": {TTL: IntPtr(128), WindowSize: IntPtr(64240), WindowScale: IntPtr(8), MSS: IntPtr(1460)},
	"Linux":   {TTL: IntPtr(64), WindowSize: IntPtr(65535), WindowScale: IntPtr(7), MSS: IntPtr(1460)},
	"macOS":   {TTL: IntPtr(64), WindowSize: IntPtr(65535), WindowScale: IntPtr(6), MSS: IntPtr(1460)},
	"iOS":     {TTL: IntPtr(64), WindowSize: IntPtr(65535), WindowScale: IntPtr(6), MSS: IntPtr(1460)},
	"Android": {TTL: IntPtr(64), WindowSize: IntPtr(65535), WindowScale: IntPtr(7), MSS: IntPtr(1460)},
}

// clientToPlatform maps the Client name in a ClientHelloID to the platform name
// used in DefaultTcpFingerprints.  Entries not in this map receive no automatic
// TCP fingerprint (all nil).
//
// Client names come from the Client field of tls.ClientHelloID in each profile.
// Safari_IOS_* profiles all use Client: "iOS" (confirmed by code search).
var clientToPlatform = map[string]string{
	// Desktop browsers
	"Chrome":  "Windows",
	"Brave":   "Windows",
	"Opera":   "Windows",
	"Safari":  "macOS",
	"Firefox": "Linux",
	// iOS – Safari_IOS_*, ZalandoIOS, NikeIOS, MMSIos, MeshIos, ConfirmedIos
	"iOS":          "iOS",
	"MMSIos":       "iOS",
	"MeshIos":      "iOS",
	"MeshIos2":     "iOS",
	"ConfirmedIos": "iOS",
	"ZalandoIosCustom": "iOS",
	"NikeIosCustom":    "iOS",
	// iPad
	"iPad": "iOS",
	// Android
	"Android":               "Android",
	"OkHttp":                "Android",
	"MeshAndroid":           "Android",
	"MeshAndroid2":          "Android",
	"ConfirmedAndroid":      "Android",
	"ZalandoAndroidCustom":  "Android",
	"NikeAndroidCustom":     "Android",
	// Cloudscraper is Chrome-based (Windows TCP fingerprint)
	"CloudflareCustom": "Windows",
}

// GetTcpFingerprint returns the TCP fingerprint for this profile.
// If the profile has an explicit tcpFingerprint set, it is returned.
// Otherwise the Client name is mapped to a platform and the platform default
// is returned.  Returns nil when no mapping exists (user must set explicitly).
func (c ClientProfile) GetTcpFingerprint() *TcpFingerprint {
	if c.tcpFingerprint != nil {
		return c.tcpFingerprint
	}
	platform, ok := clientToPlatform[c.clientHelloId.Client]
	if !ok {
		return nil
	}
	fp := DefaultTcpFingerprints[platform]
	return &fp
}

// IntPtr returns a pointer to a heap-allocated copy of v.
// Use this (not &localVar) when storing pointers in TcpFingerprint to avoid
// dangling pointers after the calling function returns.
func IntPtr(v int) *int {
	cp := v
	return &cp
}

func (c ClientProfile) GetClientHelloSpec() (tls.ClientHelloSpec, error) {
	return c.clientHelloId.ToSpec()
}

func (c ClientProfile) GetClientHelloStr() string {
	return c.clientHelloId.Str()
}

func (c ClientProfile) GetSettings() map[http2.SettingID]uint32 {
	return c.settings
}

func (c ClientProfile) GetSettingsOrder() []http2.SettingID {
	return c.settingsOrder
}

func (c ClientProfile) GetConnectionFlow() uint32 {
	return c.connectionFlow
}

func (c ClientProfile) GetPseudoHeaderOrder() []string {
	return c.pseudoHeaderOrder
}

func (c ClientProfile) GetHeaderPriority() *http2.PriorityParam {
	return c.headerPriority
}

func (c ClientProfile) GetClientHelloId() tls.ClientHelloID {
	return c.clientHelloId
}

func (c ClientProfile) GetPriorities() []http2.Priority {
	return c.priorities
}

func (c ClientProfile) GetStreamID() uint32 {
	return c.streamID
}

func (c ClientProfile) GetAllowHTTP() bool {
	return c.allowHTTP
}

func (c ClientProfile) GetHttp3Settings() map[uint64]uint64 {
	return c.http3Settings
}

func (c ClientProfile) GetHttp3SettingsOrder() []uint64 {
	return c.http3SettingsOrder
}

func (c ClientProfile) GetHttp3PriorityParam() uint32 {
	return c.http3PriorityParam
}

func (c ClientProfile) GetHttp3PseudoHeaderOrder() []string {
	return c.http3PseudoHeaderOrder
}

func (c ClientProfile) GetHttp3SendGreaseFrames() bool {
	return c.http3SendGreaseFrames
}
