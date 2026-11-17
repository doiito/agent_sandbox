package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func pristineVector(t *testing.T) (osvPristineRequest, []byte, []byte) {
	t.Helper()
	data, err := os.ReadFile("../../tests/fixtures/osv-pristine-wire-v1.txt")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(string(data))
	if len(lines) != 2 {
		t.Fatal("invalid shared pristine vectors")
	}
	request, err := hex.DecodeString(lines[0])
	if err != nil {
		t.Fatal(err)
	}
	response, err := hex.DecodeString(lines[1])
	if err != nil {
		t.Fatal(err)
	}
	value := osvPristineRequest{Operation: osvPristinePing, Binding: osvPristineBinding{ID: "0123456789abcdef01234567"}}
	for i := range value.Binding.Nonce {
		value.Binding.Nonce[i] = byte(i)
	}
	return value, request, response
}

func TestOSvPristineWireMatchesSharedGuestVector(t *testing.T) {
	request, body, response := pristineVector(t)
	frame, err := encodeOSvPristineRequest(request)
	if err != nil || len(frame) != 56 || binary.LittleEndian.Uint32(frame) != 52 || !bytes.Equal(frame[4:], body) {
		t.Fatalf("request diverged from guest vector: %x %v", frame, err)
	}
	remaining, err := decodeOSvPristineResponse(response, request)
	if err != nil || remaining != 600*time.Second {
		t.Fatalf("response diverged from guest vector: %v %v", remaining, err)
	}
	for i := range response {
		changed := bytes.Clone(response)
		changed[i] ^= 0x80
		if i >= 56 && i < 60 {
			// This field may legally become a smaller positive lifetime.
			binary.LittleEndian.PutUint32(changed[56:60], 600001)
		}
		if _, err := decodeOSvPristineResponse(changed, request); err == nil {
			t.Fatalf("accepted corrupted response byte %d", i)
		}
	}
	for size := 0; size < len(response); size++ {
		if _, err := decodeOSvPristineResponse(response[:size], request); err == nil {
			t.Fatalf("accepted response length %d", size)
		}
	}
	if _, err := decodeOSvPristineResponse(append(bytes.Clone(response), 0), request); err == nil {
		t.Fatal("accepted response suffix")
	}
	binary.LittleEndian.PutUint32(response[56:60], 0)
	if _, err := decodeOSvPristineResponse(response, request); err == nil {
		t.Fatal("accepted expired guest")
	}
}

func TestOSvPristinePrepareHasBoundedLeaseAndStrictMode(t *testing.T) {
	request, _, response := pristineVector(t)
	request.Operation, request.TTLMS = osvPristinePrepare, 1000
	response[4] = osvPristinePrepare + 1
	binary.LittleEndian.PutUint32(response[52:56], 1)
	binary.LittleEndian.PutUint32(response[56:60], 1000)
	if _, err := decodeOSvPristineResponse(response, request); err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint32(response[56:60], 1001)
	if _, err := decodeOSvPristineResponse(response, request); err == nil {
		t.Fatal("accepted an enlarged lease")
	}
	for _, mutate := range []func(*osvPristineRequest){
		func(r *osvPristineRequest) { r.Operation = 0 },
		func(r *osvPristineRequest) { r.TTLMS = 999 },
		func(r *osvPristineRequest) { r.TTLMS = 300001 },
		func(r *osvPristineRequest) { r.Binding.ID = strings.Repeat("A", 24) },
		func(r *osvPristineRequest) { r.Binding.Nonce = [16]byte{} },
		func(r *osvPristineRequest) { r.Operation = osvPristinePing },
	} {
		value := request
		mutate(&value)
		if _, err := encodeOSvPristineRequest(value); err == nil {
			t.Fatalf("accepted invalid control request: %+v", value)
		}
	}
	b := FirecrackerOSvBackend{}
	if _, err := b.exchangePristine(context.Background(), request, "/nonexistent"); err == nil {
		t.Fatal("legacy backend issued pristine control")
	}
	b.Pristine = true
	if _, err := b.Exchange(context.Background(), RunRequest{}, "/nonexistent"); err == nil {
		t.Fatal("pristine backend used legacy execution")
	}
	if _, err := b.exchangePrepared(context.Background(), RunRequest{jobID: strings.Repeat("f", 24)}, request.Binding, "/nonexistent"); err == nil {
		t.Fatal("prepared execution accepted mismatched ID")
	}
}

func TestOSvPristineControlDoesNotRetryOrIgnoreCancellation(t *testing.T) {
	for _, preparing := range []bool{false, true} {
		for _, stage := range []string{"connect", "result", "eof"} {
			name := stage
			if preparing {
				name = "prepare-" + stage
			}
			t.Run(name, func(t *testing.T) {
				request, expected, response := pristineVector(t)
				if preparing {
					request.Operation, request.TTLMS = osvPristinePrepare, 1000
					expected[4] = osvPristinePrepare
					binary.LittleEndian.PutUint32(expected[48:], 1000)
					response[4] = osvPristinePrepare + 1
					binary.LittleEndian.PutUint32(response[52:], 1)
					binary.LittleEndian.PutUint32(response[56:], 1000)
				}
				workdir, err := os.MkdirTemp("/tmp", "osp-")
				if err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(workdir)
				b := FirecrackerOSvBackend{Path: "/bin/firecracker", Pristine: true}
				path, err := jailedFirecrackerVsockPath(b.Path, workdir)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				listener, err := net.Listen("unix", path)
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				blocked, done := make(chan struct{}), make(chan error, 1)
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						done <- err
						return
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
					reader := bufio.NewReader(conn)
					line, err := reader.ReadString('\n')
					if err != nil || line != "CONNECT 5000\n" {
						done <- errors.New("invalid CONNECT")
						return
					}
					if stage != "connect" {
						_, _ = io.WriteString(conn, "OK 1073741824\n")
						frame := make([]byte, 4+len(expected))
						if _, err := io.ReadFull(reader, frame); err != nil || !bytes.Equal(frame[4:], expected) {
							done <- errors.New("invalid control frame")
							return
						}
						if stage == "eof" {
							wire := make([]byte, 4+len(response))
							binary.LittleEndian.PutUint32(wire, uint32(len(response)))
							copy(wire[4:], response)
							_, _ = conn.Write(wire)
							ack, err := reader.ReadByte()
							if err != nil || ack != 0xa5 {
								done <- errors.New("invalid control ACK")
								return
							}
						}
					}
					close(blocked)
					_, err = reader.ReadByte()
					if !errors.Is(err, io.EOF) {
						done <- errors.New("exchange retried or socket was not closed")
						return
					}
					done <- nil
				}()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				result := make(chan error, 1)
				go func() { _, err := b.exchangePristine(ctx, request, workdir); result <- err }()
				select {
				case <-blocked:
				case err := <-done:
					t.Fatal(err)
				case <-time.After(2 * time.Second):
					t.Fatal("exchange never reached blocked stage")
				}
				cancel()
				select {
				case err := <-result:
					if err == nil {
						t.Fatal("cancelled control succeeded")
					}
					if errors.Is(err, errPristinePrepareNotSent) != (preparing && stage == "connect") {
						t.Fatalf("OSv confused payload absence with lost prepared ACK/EOF: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("control ignored cancellation")
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
