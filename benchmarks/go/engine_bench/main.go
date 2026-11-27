// Command engine_bench times the Go engine without the CGO/Python layers.
//
// Splitting the measurement this way is the only way to tell an engine
// problem from a binding problem: the Python harness reports ~916 us per
// request through ExecuteRequest, and net/http alone does ~440 us on the same
// loopback origin.  If this program reproduces 916 us, the cost is in the
// engine; if it lands near net/http, the cost is in the C ABI conversion.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

func mean(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	var t float64
	for _, x := range v {
		t += x
	}
	return t / float64(len(v))
}

func pct(v []float64, q float64) float64 {
	if len(v) == 0 {
		return 0
	}
	sort.Float64s(v)
	i := int(q * float64(len(v)-1))
	return v[i]
}

func main() {
	url := flag.String("url", "", "target url")
	n := flag.Int("n", 2000, "requests per worker")
	workers := flag.Int("c", 1, "concurrent workers")
	ident := flag.String("id", "chrome_120", "client identifier")
	flag.Parse()

	opts := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profiles.MappedTLSClients[*ident]),
		tls_client.WithTimeoutSeconds(30),
	}
	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
	if err != nil {
		panic(err)
	}
	defer client.Close()

	var doNs, readNs []float64
	do := func() float64 {
		t0 := time.Now()
		resp, err := client.Get(*url)
		if err != nil {
			panic(err)
		}
		t1 := time.Now()
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		t2 := time.Now()
		if len(doNs) < cap(doNs) {
			doNs = append(doNs, float64(t1.Sub(t0).Microseconds()))
			readNs = append(readNs, float64(t2.Sub(t1).Microseconds()))
		}
		return float64(t2.Sub(t0).Microseconds())
	}
	for i := 0; i < 300; i++ {
		do()
	}

	lat := make([]float64, *workers**n)
	doNs = make([]float64, 0, 5000)
	readNs = make([]float64, 0, 5000)
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < *n; i++ {
				lat[w**n+i] = do()
			}
		}(w)
	}
	wg.Wait()
	el := time.Since(start)
	total := *workers * *n
	fmt.Printf("  split: Do(headers) mean=%7.1fus  body-read mean=%7.1fus\n",
		mean(doNs), mean(readNs))
	fmt.Printf("engine  c=%-3d rps=%8.1f  p50=%7.1fus  p95=%7.1fus  p99=%7.1fus  n=%d\n",
		*workers, float64(total)/el.Seconds(), pct(lat, 0.5), pct(lat, 0.95), pct(lat, 0.99), total)
	_ = os.Stdout
}
