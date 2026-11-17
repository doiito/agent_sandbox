// osv-http is the static HTTP/TLS client shipped in the minimal Linux guest.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// Explicit proxy environment is essential in a NIC-less guest: Go's default
// proxy helper silently bypasses all loopback targets even with NO_PROXY="".
func guestProxy(request *http.Request) (*url.URL, error) {
	if os.Getenv("NO_PROXY") != "" || os.Getenv("no_proxy") != "" {
		return http.ProxyFromEnvironment(request)
	}
	names := []string{"HTTP_PROXY", "http_proxy"}
	if request.URL.Scheme == "https" {
		names = []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"}
	}
	for _, name := range names {
		if value := os.Getenv(name); value != "" {
			proxy, err := url.Parse(value)
			if err != nil || proxy.Scheme != "http" || proxy.Host == "" || proxy.User != nil || proxy.Path != "" || proxy.RawQuery != "" || proxy.Fragment != "" {
				return nil, errors.New("invalid HTTP proxy environment")
			}
			return proxy, nil
		}
	}
	return nil, nil
}

func run(args []string, out, stderr io.Writer) int {
	flags := flag.NewFlagSet("osv-http", flag.ContinueOnError)
	flags.SetOutput(stderr)
	method := flags.String("method", "GET", "HTTP method")
	data := flags.String("data", "", "UTF-8 request body")
	ca := flags.String("cacert", "", "additional trusted CA PEM file")
	timeout := flags.Duration("timeout", 10*time.Second, "total deadline, up to 30s")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 1 || *timeout <= 0 || *timeout > 30*time.Second || len(*data) > 256<<10 {
		fmt.Fprintln(stderr, "usage: osv-http [-method POST -data text -cacert file -timeout 10s] http[s]://host/path")
		return 2
	}
	var roots *x509.CertPool
	if *ca != "" {
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		pem, err := os.ReadFile(*ca)
		if err != nil || len(pem) > 1<<20 || !roots.AppendCertsFromPEM(pem) {
			fmt.Fprintln(stderr, "cannot load additional CA")
			return 2
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, *method, flags.Arg(0), strings.NewReader(*data))
	if err != nil || request.URL.User != nil || request.URL.Host == "" || (request.URL.Scheme != "http" && request.URL.Scheme != "https") {
		fmt.Fprintln(stderr, "invalid HTTP URL")
		return 2
	}
	transport := &http.Transport{Proxy: guestProxy, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 16 << 10, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		fmt.Fprintln(stderr, "HTTP request failed:", err)
		return 1
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (512<<10)+1))
	if err != nil || len(body) > 512<<10 {
		fmt.Fprintln(stderr, "HTTP response exceeded limit or failed")
		return 1
	}
	if _, err := out.Write(body); err != nil {
		fmt.Fprintln(stderr, "HTTP output failed")
		return 1
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		fmt.Fprintln(stderr, "HTTP status:", response.StatusCode)
		return 22
	}
	return 0
}
