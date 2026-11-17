package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVsockCancellationInterruptsAckAndResult(t *testing.T) {
	for _, preparing := range []bool{false, true} {
		for _, stage := range []string{"ack", "result"} {
			name := stage
			if preparing {
				name = "prepare-" + stage
			}
			t.Run(name, func(t *testing.T) {
				backend := FirecrackerLinuxBackend{Path: "/bin/firecracker", Guest: LinuxGuestConfig{VsockPort: 5000}, Pristine: preparing}
				// Keep the test server path below sockaddr_un's limit too.
				workdir, err := os.MkdirTemp("/tmp", "vsock-")
				if err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(workdir)
				socket, err := backend.vsockPath(workdir)
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
				blocked, closed := make(chan struct{}), make(chan struct{})
				go func() {
					defer close(closed)
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
					reader := bufio.NewReader(conn)
					if _, err := reader.ReadString('\n'); err != nil {
						return
					}
					if stage == "result" {
						_, _ = io.WriteString(conn, "OK 1073741824\n")
						var request linuxJobRequest
						if json.NewDecoder(reader).Decode(&request) != nil {
							return
						}
					}
					close(blocked)
					_, _ = io.Copy(io.Discard, reader)
				}()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan error, 1)
				go func() {
					if preparing {
						binding, err := newLinuxGuestBinding("0123456789abcdef01234567")
						if err == nil {
							_, _, err = backend.ExchangeSession(ctx, linuxJobRequest{JobID: "1123456789abcdef01234567", Operation: "prepare",
								Prepare: &linuxPrepareRequest{Binding: binding, Mode: "job", TTLMS: 1000}}, workdir)
						}
						done <- err
						return
					}
					_, err := backend.Exchange(ctx, RunRequest{jobID: "0123456789abcdef01234567", Entrypoint: "/bin/true", TimeoutMS: 5000}, workdir)
					done <- err
				}()
				select {
				case <-blocked:
				case <-time.After(2 * time.Second):
					t.Fatal("exchange did not reach blocking stage")
				}
				cancel()
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("cancelled exchange succeeded")
					}
					if errors.Is(err, errPristinePrepareNotSent) != (preparing && stage == "ack") {
						t.Fatalf("transport did not distinguish before/after prepare payload: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("exchange ignored cancellation")
				}
				select {
				case <-closed:
				case <-time.After(time.Second):
					t.Fatal("exchange leaked socket")
				}
			})
		}
	}
}
