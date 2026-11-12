module github.com/bogdanfinn/tls-client

go 1.27

require (
	github.com/bdandy/go-socks4 v1.2.3
	github.com/bogdanfinn/fhttp v0.7.3
	github.com/bogdanfinn/quic-go-utls v1.0.13-utls
	github.com/bogdanfinn/utls v1.8.2-barnius
	github.com/bogdanfinn/websocket v1.5.9-barnius
	github.com/stretchr/testify v1.11.1
	golang.org/x/net v0.59.0
	golang.org/x/text v0.42.0
)

require (
	github.com/andybalholm/brotli v1.2.7 // indirect
	github.com/bdandy/go-errors v1.2.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/klauspost/compress v1.20.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/molecule-man/go-brrr v1.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// replace github.com/bogdanfinn/utls => ../utls

// replace github.com/bogdanfinn/quic-go-utls => ../quic-go-utls

// replace github.com/bogdanfinn/websocket => ../websocket

// replace github.com/bogdanfinn/fhttp => ../fhttp

// Patched in-repo: HPACK indexing policy, MaxDataFrameSize, preface ping,
// PRIORITY-frame suppression. See UPSTREAM_SYNC.md (third_party/fhttp overlay
// points). The vendored copy tracks upstream fhttp v0.7.3.
replace github.com/bogdanfinn/fhttp => ./third_party/fhttp

replace github.com/andybalholm/brotli => ./third_party/brotli
