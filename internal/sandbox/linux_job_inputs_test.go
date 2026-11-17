package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLinuxJobExecutionInputsAdmissionAndWire(t *testing.T) {
	config := Config{Backend: "firecracker-linux", Jailer: &JailerConfig{}, AllowedEntrypoints: []string{"/bin/sh"}}
	config.ApplyDefaults()
	report, err := (&Manager{config: config, backend: FirecrackerLinuxBackend{}}).Capabilities()
	if err != nil || !report.Features.Environment || !report.Features.Stdin || !report.Features.WorkingDirectory || report.Limits.MaxEnvEntries != 32 || report.Limits.MaxEnvBytes != 8192 || report.Limits.MaxStdinBytes != linuxJobStdinMaxBytes {
		t.Fatalf("Linux execution capabilities incomplete: %+v %v", report, err)
	}
	base := RunRequest{Entrypoint: "/bin/sh", Args: []string{"-c", "read input"}, Environment: map[string]string{"KEY": "中文\nvalue", "LD_LIBRARY_PATH": "/workspace/lib"}, Cwd: "/input/nested", Stdin: []byte{0, 255, 10}, jobID: "0123456789abcdef01234567"}
	base.Normalize(config)
	if err := base.Validate(config); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*RunRequest){
		func(r *RunRequest) { r.Cwd = "relative" }, func(r *RunRequest) { r.Cwd = "/workspace/\x00bad" },
		func(r *RunRequest) { r.Stdin = make([]byte, linuxJobStdinMaxBytes+1) },
		func(r *RunRequest) { r.Environment = map[string]string{"KEY": "bad\x00value"} },
		func(r *RunRequest) { r.Environment = map[string]string{"KEY": strings.Repeat("v", 1025)} },
		func(r *RunRequest) { r.Environment = map[string]string{"1BAD": "value"} },
	} {
		bad := base
		change(&bad)
		if bad.Validate(config) == nil {
			t.Fatal("invalid job inputs accepted")
		}
	}
	osv := config
	osv.Backend = "firecracker-osv"
	if base.Validate(osv) == nil {
		t.Fatal("OSv accepted Linux cwd/loader variables")
	}
	for _, prepared := range []bool{false, true} {
		for _, input := range [][]byte{nil, {}, base.Stdin, bytes.Repeat([]byte{255}, linuxJobStdinMaxBytes)} {
			req := base
			req.Stdin = input
			if err := req.Validate(config); err != nil {
				t.Fatal(err)
			}
			requestJSON, err := json.Marshal(req)
			if err != nil {
				t.Fatal(err)
			}
			var roundtrip RunRequest
			if err = json.Unmarshal(requestJSON, &roundtrip); err != nil || !reflect.DeepEqual(roundtrip.Stdin, input) {
				t.Fatal("API/launcher lost nil/empty/binary input")
			}
			root, err := os.MkdirTemp("/tmp", "job-input-")
			if err != nil {
				t.Fatal(err)
			}
			func() {
				defer os.RemoveAll(root)
				b := FirecrackerLinuxBackend{Path: "/bin/firecracker", Guest: LinuxGuestConfig{VsockPort: 5000}, Pristine: prepared}
				socket, err := b.vsockPath(root)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
					t.Fatal(err)
				}
				listener, err := net.Listen("unix", socket)
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				binding, err := newPristineBinding(req.jobID)
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						done <- err
						return
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
					reader := bufio.NewReader(conn)
					if _, err = reader.ReadString('\n'); err != nil {
						done <- err
						return
					}
					_, _ = io.WriteString(conn, "OK 5000\n")
					var wire linuxJobRequest
					if err = json.NewDecoder(reader).Decode(&wire); err != nil {
						done <- err
						return
					}
					if !reflect.DeepEqual(wire.Stdin, input) || !reflect.DeepEqual(wire.Environment, req.Environment) || wire.Cwd != req.Cwd || !reflect.DeepEqual(wire.Argv, append([]string{req.Entrypoint}, req.Args...)) {
						t.Error("cold/warm execution inputs changed on wire")
					}
					protocol := linuxGuestProtocol
					result := map[string]any{"protocol": protocol, "job_id": req.jobID, "ok": true, "exit_code": 0}
					if prepared {
						value := binding.linux()
						protocol = linuxPristineProtocol
						if wire.Binding == nil || *wire.Binding != value || wire.Operation != "run" {
							t.Error("warm job binding missing")
						}
						result["protocol"] = protocol
						result["binding"] = value
						result["guest_state"] = "prepared"
						result["pristine_revision"] = 2
						result["remaining_lifetime_ms"] = 1000
					}
					if wire.Protocol != protocol {
						t.Error("execution protocol changed")
					}
					payload, err := json.Marshal(result)
					if err == nil {
						_, err = conn.Write(append([]byte(linuxResultPrefix), append(payload, '\n')...))
					}
					done <- err
				}()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if prepared {
					_, ok, err := (linuxPristineVMBackend{b}).runVM(ctx, req, binding, root)
					if err != nil || !ok {
						t.Fatalf("warm: %v %t", err, ok)
					}
				} else if _, err := b.Exchange(ctx, req, root); err != nil {
					t.Fatal(err)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			}()
		}
	}
}
