package otlp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func testConfig(endpoint string) Config {
	return Config{Endpoint: endpoint, AllowLoopbackHTTP: true, Signals: []string{"logs"}, IntervalMS: 60000}
}

func closeExporter(t *testing.T, e *Exporter) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = e.Close(ctx)
	select {
	case <-e.Done():
	case <-time.After(2 * time.Second):
		t.Error("OTLP worker did not exit")
	}
}

func TestConfigDefaultsAndCallerMutationIsolation(t *testing.T) {
	sample := 0
	c := testConfig("http://127.0.0.1:4318/base")
	c.QueueCapacity, c.TraceSamplePermille = 2, &sample
	e, err := New(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeExporter(t, e)
	c.Signals[0], sample = "metrics", 1000
	if e.config.BatchSize != 2 || e.config.ServiceName != "osv-sandbox" || e.config.Source != "host.api" ||
		e.config.Signals[0] != "logs" || *e.config.TraceSamplePermille != 0 || e.urls[1] != "http://127.0.0.1:4318/base/v1/logs" {
		t.Fatal("defaults, endpoint join or copied configuration changed")
	}
}

func TestConfigRejectsInvalidPolicy(t *testing.T) {
	for _, endpoint := range []string{"", "ftp://127.0.0.1", "http://localhost:4318", "http://192.0.2.1", "https://user:secret@collector.test", "https://collector.test/?token=secret", "https://collector.test/#hidden", "https://collector.test/a/../b", "https://collector.test/a//b", "https://collector.test:0", "https://collector.test:65536", "https://collector.test/%2e%2e/b"} {
		t.Run(endpoint, func(t *testing.T) {
			c := testConfig(endpoint)
			if c.Validate() == nil {
				t.Fatal("invalid endpoint accepted")
			}
		})
	}
	mutations := []func(*Config){
		func(c *Config) { c.AllowLoopbackHTTP = false },
		func(c *Config) { c.IntervalMS = 99 }, func(c *Config) { c.TimeoutMS = 30001 },
		func(c *Config) { c.QueueCapacity = 16385 }, func(c *Config) { c.BatchSize = 1025 },
		func(c *Config) { c.MaxBatchBytes = 65535 }, func(c *Config) { c.Signals = []string{"logs", "logs"} },
		func(c *Config) { c.Signals = []string{"profiles"} }, func(c *Config) { c.Source = "untrusted-pretending-root" },
		func(c *Config) { c.ServiceName = "contains newline\n" }, func(c *Config) { c.ClientCertFile = "/one.pem" },
		func(c *Config) { c.BearerTokenFile = "relative" }, func(c *Config) { n := -1; c.TraceSamplePermille = &n },
	}
	for index, mutate := range mutations {
		c := testConfig("http://127.0.0.1:4318")
		mutate(&c)
		if c.Validate() == nil {
			t.Errorf("invalid config mutation %d accepted", index)
		}
	}
}

func TestConfigValidationDoesNotOpenCredentials(t *testing.T) {
	c := testConfig("https://collector.test")
	c.BearerTokenFile = "/nonexistent/private-token"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if e, err := New(c, nil); err == nil {
		closeExporter(t, e)
		t.Fatal("missing credential accepted at construction")
	}
}

func TestPrivateCredentialsAndNonregularFiles(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "token")
	if err := os.WriteFile(secret, []byte("test-private-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := testConfig("http://127.0.0.1:4318")
	c.BearerTokenFile = secret
	e, err := New(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	closeExporter(t, e)
	if err := os.Chmod(secret, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(c, nil); err == nil {
		t.Fatal("public credential file accepted")
	}
	if err := os.Chmod(secret, 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(secret, alias); err != nil {
		t.Fatal(err)
	}
	c.BearerTokenFile = alias
	if _, err := New(c, nil); err == nil {
		t.Fatal("private symlink accepted")
	}
	pipe := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := boundedFile(pipe, 4096, true); err == nil || time.Since(started) > time.Second {
		t.Fatal("credential FIFO accepted or blocked")
	}
	for _, content := range []string{"", "Bearer\nINJECTION", strings.Repeat("x", 4097)} {
		if err := os.WriteFile(secret, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		c.BearerTokenFile = secret
		if _, err := New(c, nil); err == nil {
			t.Fatal("invalid token accepted")
		}
	}
}

func TestMetricsSourceRequiredOnlyForEnabledSignal(t *testing.T) {
	c := testConfig("http://127.0.0.1:4318")
	c.Signals = []string{"metrics"}
	if _, err := New(c, nil); err == nil {
		t.Fatal("missing metric source accepted")
	}
	e, err := New(c, func(context.Context) ([]Metric, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	closeExporter(t, e)
}
