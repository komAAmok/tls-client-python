// Command benchserver is the local origin used by benchmarks/harness.py.
//
// The harness must measure the client, not the fixture.  A Python asyncio
// echo server tops out around 800 req/s on one core, which is the same order
// as the numbers under test, so it silently becomes the bottleneck.  This
// server keeps HTTP/1.1 keep-alive and serves a body whose length the request
// path selects, and saturates far above the client.
//
//	go run ./benchmarks/server -addr 127.0.0.1:0 -print-port
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
)

var bodyCache sync.Map // int -> []byte

func bodyFor(n int) []byte {
	if v, ok := bodyCache.Load(n); ok {
		return v.([]byte)
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	bodyCache.Store(n, b)
	return b
}

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address")
	printPort := flag.Bool("print-port", false, "print the bound address on stdout, then serve")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		n := 1024
		if v := r.URL.Query().Get("len"); v != "" {
			if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
				n = parsed
			}
		}
		body := bodyFor(n)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", strconv.Itoa(n))
		w.WriteHeader(200)
		if r.Method != http.MethodHead && n > 0 {
			_, _ = w.Write(body)
		}
	})

	srv := &http.Server{Handler: mux}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	if *printPort {
		fmt.Println(ln.Addr().String())
		_ = os.Stdout.Sync()
	}
	if err := srv.Serve(ln); err != nil {
		log.Fatal(err)
	}
}
