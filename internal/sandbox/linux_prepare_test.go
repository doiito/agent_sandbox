package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPristinePreparationInputAndBindingValidation(t *testing.T) {
	binding, err := newLinuxGuestBinding("0123456789abcdef01234567")
	if err != nil || !binding.valid() {
		t.Fatalf("binding: %+v %v", binding, err)
	}
	other, err := newLinuxGuestBinding(binding.SessionID)
	if err != nil || other.Nonce == binding.Nonce {
		t.Fatal("fresh preparation did not receive a fresh nonce")
	}
	base := linuxPrepareRequest{Binding: binding, Mode: "session", TTLMS: 30000,
		InputFiles: []InputFile{{Path: "nested/prompt", Data: []byte{0, 1, 255}}}}
	if err := base.validate(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"../escape", "/etc/passwd", "a//b", "a/./b", "a\\b", "bad\nname", strings.Repeat("a/", 16) + "file", strings.Repeat("x", 256)} {
		r := base
		r.InputFiles = []InputFile{{Path: path}}
		if r.validate() == nil {
			t.Fatalf("invalid input accepted: %q", path)
		}
	}
	r := base
	r.InputFiles = []InputFile{{Path: "a"}, {Path: "a-"}, {Path: "a/b"}}
	if r.validate() == nil {
		t.Fatal("file/parent conflict accepted")
	}
	r = base
	r.InputFiles = []InputFile{{Path: "data", Data: make([]byte, 512*1024+1)}}
	if r.validate() == nil {
		t.Fatal("oversized preparation accepted")
	}
	r = base
	r.Binding.Nonce = strings.Repeat("A", 64)
	if r.validate() == nil {
		t.Fatal("invalid nonce accepted")
	}
	r = base
	r.TTLMS = 600001
	if r.validate() == nil {
		t.Fatal("unbounded lease accepted")
	}
	r = base
	r.Mode, r.TTLMS = "job", 300001
	if r.validate() == nil {
		t.Fatal("session hard lifetime leaked into job lease limit")
	}
}

func TestPristineExchangeRejectsForgedBindingAndDowngrade(t *testing.T) {
	for _, scenario := range []string{"valid", "long-session", "nonce", "protocol", "state", "lease", "revision", "unbounded"} {
		t.Run(scenario, func(t *testing.T) {
			ttlMS := 30000
			if scenario == "long-session" {
				ttlMS = 590000
			}
			b := FirecrackerLinuxBackend{Path: "/bin/firecracker", Guest: LinuxGuestConfig{VsockPort: 5000}, Pristine: true}
			root, err := os.MkdirTemp("/tmp", "prep-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			socket, err := b.vsockPath(root)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				reader := bufio.NewReader(conn)
				if _, err = reader.ReadString('\n'); err != nil {
					return
				}
				_, _ = io.WriteString(conn, "OK 5000\n")
				var request linuxJobRequest
				if json.NewDecoder(reader).Decode(&request) != nil {
					return
				}
				if request.Protocol != linuxPristineProtocol || request.Prepare == nil || string(request.Prepare.InputFiles[0].Data) != "binary\x00input" {
					t.Error("preparation wire fields changed")
					return
				}
				binding := request.Prepare.Binding
				response := map[string]any{"protocol": linuxPristineProtocol, "job_id": request.JobID, "ok": true, "binding": binding, "guest_state": "prepared", "remaining_lifetime_ms": ttlMS, "pristine_revision": 2}
				switch scenario {
				case "nonce":
					binding.Nonce = strings.Repeat("b", 64)
					response["binding"] = binding
				case "protocol":
					response["protocol"] = linuxSessionProtocol
				case "state":
					response["guest_state"] = "pristine"
				case "revision":
					delete(response, "pristine_revision")
				case "lease":
					response["remaining_lifetime_ms"] = 30001
				case "unbounded":
					response["remaining_lifetime_ms"] = sessionMaxLifetimeMS + 1
				}
				data, _ := json.Marshal(response)
				_, _ = conn.Write(append([]byte(linuxResultPrefix), append(data, '\n')...))
			}()
			binding, _ := newLinuxGuestBinding("0123456789abcdef01234567")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, ok, err := b.ExchangeSession(ctx, linuxJobRequest{JobID: "123456789abcdef012345678", Operation: "prepare",
				Prepare: &linuxPrepareRequest{Binding: binding, Mode: "session", TTLMS: ttlMS, InputFiles: []InputFile{{Path: "file", Data: []byte("binary\x00input")}}}}, root)
			if scenario == "valid" || scenario == "long-session" {
				if err != nil || !ok {
					t.Fatalf("valid prep rejected: %v %t", err, ok)
				}
			} else if err == nil {
				t.Fatalf("%s accepted", scenario)
			}
			<-finished
		})
	}
}
