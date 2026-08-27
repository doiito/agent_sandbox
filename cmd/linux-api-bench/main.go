// Command linux-api-bench measures the complete firecracker-linux HTTP path.
// It intentionally uses the public API rather than importing manager internals.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

type options struct {
	url         string
	iterations  int
	warmup      int
	concurrency int
	timeout     time.Duration
	memoryMiB   int
	vcpus       int
	output      string
	tlsCA       string
	tlsCert     string
	tlsKey      string
}

type apiResult struct {
	State      string `json:"state"`
	Backend    string `json:"backend"`
	DurationMS int64  `json:"duration_ms"`
	ProtocolOK bool   `json:"protocol_ok"`
}

type sample struct {
	Index        int    `json:"index"`
	Success      bool   `json:"success"`
	HTTPStatus   int    `json:"http_status"`
	LatencyUS    int64  `json:"latency_us"`
	ServerTimeMS int64  `json:"server_duration_ms"`
	Error        string `json:"error,omitempty"`
}

type report struct {
	GeneratedAt       string   `json:"generated_at"`
	URL               string   `json:"url"`
	Iterations        int      `json:"iterations"`
	Concurrency       int      `json:"concurrency"`
	Successes         int      `json:"successes"`
	Failures          int      `json:"failures"`
	ElapsedMS         int64    `json:"elapsed_ms"`
	ThroughputJobsSec float64  `json:"throughput_jobs_sec"`
	LatencyP50US      int64    `json:"latency_p50_us"`
	LatencyP90US      int64    `json:"latency_p90_us"`
	LatencyP99US      int64    `json:"latency_p99_us"`
	LatencyMaxUS      int64    `json:"latency_max_us"`
	Samples           []sample `json:"samples"`
}

func main() {
	var o options
	flag.StringVar(&o.url, "url", "http://127.0.0.1:18081/v1/jobs", "sandbox jobs endpoint")
	flag.IntVar(&o.iterations, "iterations", 30, "measured jobs")
	flag.IntVar(&o.warmup, "warmup", 2, "unmeasured jobs")
	flag.IntVar(&o.concurrency, "concurrency", 1, "parallel requests")
	flag.DurationVar(&o.timeout, "timeout", 10*time.Second, "HTTP timeout")
	flag.IntVar(&o.memoryMiB, "memory-mib", 256, "guest memory")
	flag.IntVar(&o.vcpus, "vcpus", 1, "guest vCPUs")
	flag.StringVar(&o.output, "output", "", "optional JSON report path")
	flag.StringVar(&o.tlsCA, "tls-ca", "", "PEM CA for the production HTTPS endpoint")
	flag.StringVar(&o.tlsCert, "tls-cert", "", "PEM mTLS client certificate")
	flag.StringVar(&o.tlsKey, "tls-key", "", "PEM mTLS client private key")
	flag.Parse()
	if o.iterations < 1 || o.warmup < 0 || o.concurrency < 1 || o.memoryMiB < 16 || o.vcpus < 1 || o.timeout < time.Second {
		fatalf("invalid numeric option")
	}
	token := os.Getenv("OSV_SANDBOX_TOKEN")
	if token == "" {
		fatalf("OSV_SANDBOX_TOKEN is required")
	}
	client, err := newHTTPClient(o)
	if err != nil {
		fatalf("configure HTTP client: %v", err)
	}
	for i := 0; i < o.warmup; i++ {
		if got := runOne(client, token, o, -1); !got.Success {
			fatalf("warmup failed: %s", got.Error)
		}
	}
	samples := make([]sample, o.iterations)
	jobs := make(chan int)
	var wg sync.WaitGroup
	started := time.Now()
	for worker := 0; worker < o.concurrency; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				samples[index] = runOne(client, token, o, index)
			}
		}()
	}
	for index := range samples {
		jobs <- index
	}
	close(jobs)
	wg.Wait()
	elapsed := time.Since(started)
	r := summarize(o, samples, elapsed)
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		fatalf("encode report: %v", err)
	}
	data = append(data, '\n')
	if o.output != "" {
		if err := os.WriteFile(o.output, data, 0o600); err != nil {
			fatalf("write report: %v", err)
		}
	}
	_, _ = os.Stdout.Write(data)
	if r.Failures != 0 {
		os.Exit(1)
	}
}

func newHTTPClient(o options) (*http.Client, error) {
	client := &http.Client{Timeout: o.timeout}
	provided := 0
	for _, path := range []string{o.tlsCA, o.tlsCert, o.tlsKey} {
		if path != "" {
			provided++
		}
	}
	if provided == 0 {
		return client, nil
	}
	if provided != 3 {
		return nil, fmt.Errorf("tls-ca, tls-cert and tls-key must be supplied together")
	}
	caPEM, err := os.ReadFile(o.tlsCA)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA contains no certificate")
	}
	certificate, err := tls.LoadX509KeyPair(o.tlsCert, o.tlsKey)
	if err != nil {
		return nil, fmt.Errorf("load client key pair: %w", err)
	}
	client.Transport = &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots, Certificates: []tls.Certificate{certificate},
	}}
	return client, nil
}

func runOne(client *http.Client, token string, o options, index int) sample {
	payload, _ := json.Marshal(map[string]any{
		"entrypoint": "/bin/true", "memory_mib": o.memoryMiB,
		"vcpus": o.vcpus, "timeout_ms": int(o.timeout.Milliseconds()) - 250,
	})
	req, err := http.NewRequest(http.MethodPost, o.url, bytes.NewReader(payload))
	if err != nil {
		return sample{Index: index, Error: err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	started := time.Now()
	response, err := client.Do(req)
	latency := time.Since(started).Microseconds()
	if err != nil {
		return sample{Index: index, LatencyUS: latency, Error: err.Error()}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	got := sample{Index: index, HTTPStatus: response.StatusCode, LatencyUS: latency}
	if err != nil {
		got.Error = err.Error()
		return got
	}
	var result apiResult
	if err := json.Unmarshal(body, &result); err != nil {
		got.Error = fmt.Sprintf("decode response: %v", err)
		return got
	}
	got.ServerTimeMS = result.DurationMS
	got.Success = response.StatusCode == http.StatusOK && result.State == "succeeded" &&
		result.Backend == "firecracker-linux" && result.ProtocolOK
	if !got.Success {
		got.Error = fmt.Sprintf("status=%d state=%s backend=%s protocol_ok=%t", response.StatusCode, result.State, result.Backend, result.ProtocolOK)
	}
	return got
}

func summarize(o options, samples []sample, elapsed time.Duration) report {
	latencies := make([]int64, 0, len(samples))
	r := report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano), URL: o.url,
		Iterations: len(samples), Concurrency: o.concurrency,
		ElapsedMS: elapsed.Milliseconds(), Samples: samples,
	}
	for _, got := range samples {
		if got.Success {
			r.Successes++
			latencies = append(latencies, got.LatencyUS)
		} else {
			r.Failures++
		}
	}
	r.ThroughputJobsSec = float64(r.Successes) / elapsed.Seconds()
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	if len(latencies) != 0 {
		r.LatencyP50US = percentile(latencies, 50)
		r.LatencyP90US = percentile(latencies, 90)
		r.LatencyP99US = percentile(latencies, 99)
		r.LatencyMaxUS = latencies[len(latencies)-1]
	}
	return r
}

func percentile(sorted []int64, percent int) int64 {
	index := (len(sorted)*percent + 99) / 100
	if index < 1 {
		index = 1
	}
	return sorted[index-1]
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
