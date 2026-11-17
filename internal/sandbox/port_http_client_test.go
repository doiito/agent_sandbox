package sandbox

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

type portHTTPRoundTrip func(*http.Request) (*http.Response, error)

func (f portHTTPRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPortHTTPClientRejectsUnboundUpgrade(t *testing.T) {
	r := portOpenRequest(1)
	sid := strings.Repeat("a", 24)
	for _, key := range []string{"Upgrade", "X-OSV-Session-ID", "X-OSV-Connection-ID", "X-OSV-Port", "Connection", "HTTP2", "read_only_body"} {
		t.Run(key, func(t *testing.T) {
			local, peer := net.Pipe()
			defer peer.Close()
			defer local.Close()
			client := &http.Client{Transport: portHTTPRoundTrip(func(req *http.Request) (*http.Response, error) {
				h := http.Header{}
				h.Set("Upgrade", "osv-port/1")
				h.Set("Connection", "Upgrade")
				h.Set("X-OSV-Session-ID", sid)
				h.Set("X-OSV-Connection-ID", r.ID)
				h.Set("X-OSV-Port", "8080")
				response := &http.Response{StatusCode: 101, ProtoMajor: 1, ProtoMinor: 1, Header: h, Body: local}
				switch key {
				case "HTTP2":
					response.ProtoMajor = 2
				case "read_only_body":
					response.Body = io.NopCloser(strings.NewReader(""))
				default:
					h.Set(key, "wrong")
				}
				return response, nil
			})}
			if tunnel, err := OpenHTTPPortTunnel(context.Background(), context.Background(), client, "https://api.invalid", "secret", sid, r); err == nil {
				tunnel.Close()
				t.Fatal("unbound upgrade accepted")
			}
		})
	}
}

func TestPortHTTPClientStartupCancellationIsIndependentAfterAck(t *testing.T) {
	r := portOpenRequest(1)
	sid := strings.Repeat("a", 24)
	local, peer := net.Pipe()
	defer peer.Close()
	client := &http.Client{Timeout: 30 * time.Millisecond, Transport: portHTTPRoundTrip(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 101, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"Connection": {"Upgrade"}, "Upgrade": {"osv-port/1"}, "X-Osv-Session-Id": {sid}, "X-Osv-Connection-Id": {r.ID}, "X-Osv-Port": {"8080"}}, Body: local}, nil
	})}
	start, cancel := context.WithCancel(context.Background())
	tunnel, err := OpenHTTPPortTunnel(start, context.Background(), client, "https://api.invalid", "secret", sid, r)
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	cancel()
	finished := make(chan error, 1)
	go func() {
		defer peer.Close()
		time.Sleep(50 * time.Millisecond)
		if err := writePortBytes(peer, testPortFrame(portEOFFrame, nil)); err != nil {
			finished <- err
			return
		}
		if kind, _, err := readTestPortFrame(peer); err != nil || kind != portEOFFrame {
			if err == nil {
				err = errPortProtocol
			}
			finished <- err
			return
		}
		data, _ := json.Marshal(SessionPortInfo{ID: r.ID, Port: r.Port, Status: "completed"})
		finished <- writePortBytes(peer, testPortFrame(portFinishedFrame, data))
	}()
	if frame, err := tunnel.Next(); err != nil || frame.Kind != "eof" {
		t.Fatal(frame, err)
	}
	if err := tunnel.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if frame, err := tunnel.Next(); err != nil || frame.Kind != "finished" || frame.Info.Status != "completed" {
		t.Fatal(frame, err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}
