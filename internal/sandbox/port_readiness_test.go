package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testPortReadiness(state string) map[string]any {
	return map[string]any{
		"revision": 1, "protocol": linuxPortProtocol, "port": 5004, "target": "ipv4_loopback", "state": state,
		"max_connections": 8, "max_records": 256, "max_frame_bytes": 16384, "max_bytes": 67108864, "max_duration_ms": 300000}
}

func readinessTransport(t *testing.T, b FirecrackerLinuxBackend, respond func(linuxJobRequest) map[string]any) string {
	t.Helper()
	work, err := os.MkdirTemp("/tmp", "pr-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(work) })
	socket, err := b.vsockPath(work)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				reader := bufio.NewReader(c)
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if line != "CONNECT 5000\n" {
					t.Error(line)
					return
				}
				if _, err = io.WriteString(c, "OK 1073742000\n"); err != nil {
					return
				}
				var r linuxJobRequest
				if json.NewDecoder(reader).Decode(&r) != nil {
					return
				}
				result := respond(r)
				result["protocol"] = linuxSessionProtocol
				if b.Pristine {
					result["protocol"] = linuxPristineProtocol
				}
				result["job_id"] = r.JobID
				result["ok"] = true
				if b.Pristine {
					result["pristine_revision"] = 2
					result["guest_state"] = "pristine"
					result["remaining_lifetime_ms"] = 10000
					if r.Binding != nil {
						result["binding"] = r.Binding
						result["guest_state"] = "prepared"
					}
					if r.Prepare != nil {
						result["binding"] = r.Prepare.Binding
						result["guest_state"] = "prepared"
					}
				}
				data, _ := json.Marshal(result)
				_, _ = fmt.Fprintf(c, "%s%s\n", linuxResultPrefix, data)
			}()
		}
	}()
	t.Cleanup(func() { _ = l.Close(); <-done; workers.Wait() })
	return work
}

func TestPortReadinessActualExchangeColdWarmPrepareAndBoundPing(t *testing.T) {
	for _, mode := range []string{"cold", "warm", "session", "job", "bound"} {
		for _, fault := range []string{"valid", "missing", "state", "target", "revision", "protocol", "port", "max_connections", "max_records", "max_frame_bytes", "max_bytes", "max_duration_ms", "unknown"} {
			t.Run(mode+"/"+fault, func(t *testing.T) {
				b := FirecrackerLinuxBackend{Path: "/bin/firecracker", Guest: LinuxGuestConfig{VsockPort: 5000}, PortForward: true, Pristine: mode != "cold"}
				state := "session"
				if mode == "warm" {
					state = "pending"
				}
				work := readinessTransport(t, b, func(linuxJobRequest) map[string]any {
					result := map[string]any{"proxy_revision": 1}
					proof := testPortReadiness(state)
					if fault == "missing" || mode == "job" && fault == "valid" {
						return result
					}
					switch fault {
					case "state":
						proof["state"] = "wrong"
					case "target":
						proof["target"] = "host"
					case "protocol":
						proof["protocol"] = "other"
					case "unknown":
						proof["address"] = "host.invalid"
					case "valid":
					default:
						proof[fault] = 0
					}
					result["port_service"] = proof
					return result
				})
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				var err error
				switch mode {
				case "cold":
					_, _, err = b.ExchangeSession(ctx, linuxJobRequest{JobID: strings.Repeat("a", 24), Operation: "ping"}, work)
				case "warm":
					_, err = (linuxPristineVMBackend{b}).probeVM(ctx, work)
				case "session", "job":
					binding, _ := newPristineBinding(strings.Repeat("a", 24))
					err = (linuxPristineVMBackend{b}).prepareVM(ctx, pristinePreparation{Binding: binding, Mode: mode, TTLMS: 10000}, work)
				case "bound":
					binding, _ := newLinuxGuestBinding(strings.Repeat("a", 24))
					_, _, err = b.ExchangeSession(ctx, linuxJobRequest{JobID: strings.Repeat("b", 24), Operation: "ping", Binding: &binding}, work)
				}
				wantSuccess := fault == "valid" || mode == "job" && fault == "missing"
				if (err == nil) != wantSuccess {
					t.Fatal("readiness acceptance", mode, fault, err)
				}
			})
		}
	}
}
