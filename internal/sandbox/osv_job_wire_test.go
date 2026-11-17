package sandbox

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOSvJobWireRejectsBadIdentityAndLengths(t *testing.T) {
	id := "0123456789abcdef01234567"
	var nonce [16]byte
	request := RunRequest{Entrypoint: "/task-probe.so", Args: []string{"hello world", "$literal"}, TimeoutMS: 1000, jobID: id}
	frame, err := encodeOSvJobRequest(request, nonce, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(frame[:4]) != uint32(len(frame)-4) ||
		!bytes.Contains(frame, []byte("$literal")) {
		t.Fatal("request framing or literal argument corrupted")
	}
	response := make([]byte, 64+3)
	copy(response[:4], "OSJ1")
	response[4] = osvJobResponse
	copy(response[8:32], id)
	copy(response[32:48], nonce[:])
	binary.LittleEndian.PutUint32(response[52:56], 7)
	binary.LittleEndian.PutUint32(response[56:60], 3)
	copy(response[64:], "out")
	got, err := decodeOSvJobResult(response, id, nonce, 1024)
	if err != nil || got.ExitCode != 7 || string(got.Stdout) != "out" {
		t.Fatalf("valid result rejected: %+v %v", got, err)
	}
	mutations := []func([]byte){
		func(p []byte) { p[4] = 3 },
		func(p []byte) { p[5] = 4 },
		func(p []byte) { p[8] = 'A' },
		func(p []byte) { p[32] ^= 1 },
		func(p []byte) { binary.LittleEndian.PutUint32(p[56:60], 1000) },
		func(p []byte) { binary.LittleEndian.PutUint32(p[48:52], 1) },
	}
	for index, mutate := range mutations {
		bad := bytes.Clone(response)
		mutate(bad)
		if _, err := decodeOSvJobResult(bad, id, nonce, 1024); err == nil {
			t.Errorf("accepted malformed result %d", index)
		}
	}
	if _, err := decodeOSvJobResult(append(response, 'x'), id, nonce, 1024); err == nil {
		t.Fatal("accepted trailing result bytes")
	}
	var prefix [4]byte
	binary.LittleEndian.PutUint32(prefix[:], 10000)
	if _, err := readOSvFrame(bytes.NewReader(prefix[:]), 2048); err == nil {
		t.Fatal("accepted oversized frame")
	}
}

func TestOSvJobArgvBoundaryMatchesAdmissionAndWire(t *testing.T) {
	path := "/task-probe.so"
	config := Config{Backend: "firecracker-osv", Jailer: &JailerConfig{}, AllowedEntrypoints: []string{path}}
	config.ApplyDefaults()
	var nonce [16]byte
	check := func(args []string, accepted bool) {
		t.Helper()
		req := RunRequest{Entrypoint: path, Args: args, jobID: "0123456789abcdef01234567"}
		req.Normalize(config)
		admission := req.Validate(config)
		_, wire := encodeOSvJobRequest(req, nonce, 1024)
		if accepted && (admission != nil || wire != nil) {
			t.Fatalf("valid argv boundary rejected: admission=%v wire=%v", admission, wire)
		}
		if !accepted && (admission == nil || wire == nil) {
			t.Fatalf("invalid argv boundary accepted: admission=%v wire=%v", admission, wire)
		}
	}
	check(make([]string, 64), true)
	check(make([]string, 65), false)
	full := []string{strings.Repeat("a", 4096-len(path))}
	for range 7 {
		full = append(full, strings.Repeat("b", 4096))
	}
	check(full, true)
	full[0] += "a"
	check(full, false)
}

func TestOSvJobEnvironmentAdmissionAndCanonicalWire(t *testing.T) {
	const path = "/task-probe.so"
	config := Config{Backend: "firecracker-osv", Jailer: &JailerConfig{}, AllowedEntrypoints: []string{path}}
	config.ApplyDefaults()
	var nonce [16]byte
	req := RunRequest{Entrypoint: path, Environment: map[string]string{
		"SANDBOX_Z": "last", "SANDBOX_A": "", "SANDBOX_TEST_MARKER": "native-env-ok",
	}, jobID: "0123456789abcdef01234567"}
	req.Normalize(config)
	if err := req.Validate(config); err != nil {
		t.Fatal(err)
	}
	frame, err := encodeOSvJobRequest(req, nonce, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(frame[4:8]) != osvJobMagic || frame[9] != 1 {
		t.Fatal("environment extension flag absent")
	}
	if !bytes.Contains(frame, []byte("SANDBOX_A")) ||
		bytes.Index(frame, []byte("SANDBOX_A")) >= bytes.Index(frame, []byte("SANDBOX_Z")) {
		t.Fatal("environment was not encoded in canonical name order")
	}
	base := RunRequest{Entrypoint: path, jobID: req.jobID, TimeoutMS: req.TimeoutMS}
	legacy, err := encodeOSvJobRequest(base, nonce, 1024)
	if err != nil || legacy[9] != 0 || len(legacy) != 4+osvJobHeaderLen+len(path)+12 {
		t.Fatalf("legacy frame changed: %v", err)
	}
	invalid := []map[string]string{
		{"1BAD": "value"}, {"A-B": "value"}, {"LD_PRELOAD": "value"},
		{"OSV_DEBUG": "value"}, {"GOOD": "bad\x00value"},
		{"GOOD": strings.Repeat("v", 1025)},
		{"GOOD": strings.Repeat("v", 1024), "B": strings.Repeat("v", 1024),
			"C": strings.Repeat("v", 1024), "D": strings.Repeat("v", 1024),
			"E": strings.Repeat("v", 1024), "F": strings.Repeat("v", 1024),
			"G": strings.Repeat("v", 1024), "H": strings.Repeat("v", 1024),
			"I": strings.Repeat("v", 1024)},
	}
	tooMany := map[string]string{}
	for index := range 33 {
		tooMany[fmt.Sprintf("KEY_%02d", index)] = ""
	}
	invalid = append(invalid, tooMany)
	for index, environment := range invalid {
		bad := req
		bad.Environment = environment
		if err := bad.Validate(config); err == nil {
			t.Errorf("admission accepted invalid environment %d", index)
		}
		if _, err := encodeOSvJobRequest(bad, nonce, 1024); err == nil {
			t.Errorf("wire accepted invalid environment %d", index)
		}
	}
	linux := config
	linux.Backend = "firecracker-linux"
	if err := req.Validate(linux); err != nil {
		t.Fatal("Linux backend rejected a valid environment")
	}
}

func TestOSvJobStdinAdmissionAndWire(t *testing.T) {
	const path = "/task-probe.so"
	config := Config{Backend: "firecracker-osv", Jailer: &JailerConfig{}, AllowedEntrypoints: []string{path}}
	config.ApplyDefaults()
	var nonce [16]byte
	base := RunRequest{Entrypoint: path, jobID: "0123456789abcdef01234567"}
	base.Normalize(config)
	encodedEmpty, err := json.Marshal(RunRequest{Stdin: []byte{}})
	if err != nil || !bytes.Contains(encodedEmpty, []byte(`"stdin":""`)) {
		t.Fatalf("empty stdin was lost on API to launcher JSON hop: %s %v", encodedEmpty, err)
	}
	var decodedEmpty RunRequest
	if err := json.Unmarshal(encodedEmpty, &decodedEmpty); err != nil || decodedEmpty.Stdin == nil {
		t.Fatalf("empty stdin was lost on launcher decode: %v", err)
	}
	legacy, err := encodeOSvJobRequest(base, nonce, 1024)
	if err != nil || legacy[9] != 0 {
		t.Fatalf("legacy frame changed: %v", err)
	}
	for _, input := range [][]byte{{}, {'A', 0, 'B', 0xff, '\n'}, bytes.Repeat([]byte{0x5a}, osvJobStdinMaxBytes)} {
		req := base
		req.Stdin = input
		if err := req.Validate(config); err != nil {
			t.Fatal(err)
		}
		frame, err := encodeOSvJobRequest(req, nonce, 1024)
		if err != nil || frame[9] != 2 ||
			!bytes.Equal(frame[4:8], legacy[4:8]) ||
			!bytes.Equal(frame[10:len(legacy)], legacy[10:]) ||
			!bytes.Equal(frame[len(legacy)+2:], input) {
			t.Fatalf("stdin frame does not preserve legacy prefix: %v", err)
		}
		if got := binary.LittleEndian.Uint16(frame[len(legacy):]); int(got) != len(input) {
			t.Fatalf("stdin length %d != %d", got, len(input))
		}
	}
	bad := base
	bad.Stdin = bytes.Repeat([]byte{0}, osvJobStdinMaxBytes+1)
	if err := bad.Validate(config); err == nil {
		t.Fatal("oversized stdin admitted")
	}
	if _, err := encodeOSvJobRequest(bad, nonce, 1024); err == nil {
		t.Fatal("oversized stdin encoded")
	}
	linux := config
	linux.Backend = "firecracker-linux"
	bad.Stdin = []byte{}
	if err := bad.Validate(linux); err != nil {
		t.Fatal("Linux rejected bounded empty stdin")
	}
	combined := base
	combined.Environment = map[string]string{"A": "B"}
	combined.Stdin = []byte{'x'}
	frame, err := encodeOSvJobRequest(combined, nonce, 1024)
	if err != nil || frame[9] != 3 || frame[len(frame)-1] != 'x' {
		t.Fatalf("combined environment and stdin frame failed: %v", err)
	}
}

func TestOSvBackendExchangeBindsNonceAndRequiresEOF(t *testing.T) {
	for _, badNonce := range []bool{false, true} {
		workdir := filepath.Join(t.TempDir(), "job-a1b2")
		path, err := jailedFirecrackerVsockPath("/usr/bin/firecracker", workdir)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		parent, err := os.Open(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		defer parent.Close()
		listener, err := net.Listen("unix", fmt.Sprintf("/proc/self/fd/%d/%s", parent.Fd(), filepath.Base(path)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		serverDone := make(chan error, 1)
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				serverDone <- err
				return
			}
			defer conn.Close()
			var connect [13]byte
			if _, err = io.ReadFull(conn, connect[:]); err != nil {
				serverDone <- err
				return
			}
			if string(connect[:]) != "CONNECT 5000\n" {
				serverDone <- io.ErrUnexpectedEOF
				return
			}
			_, _ = conn.Write([]byte("OK 42\n"))
			var length [4]byte
			if _, err = io.ReadFull(conn, length[:]); err != nil {
				serverDone <- err
				return
			}
			body := make([]byte, binary.LittleEndian.Uint32(length[:]))
			if _, err = io.ReadFull(conn, body); err != nil {
				serverDone <- err
				return
			}
			result := make([]byte, 64+2)
			copy(result[:4], "OSJ1")
			result[4] = osvJobResponse
			copy(result[8:48], body[8:48])
			if badNonce {
				result[32] ^= 1
			}
			binary.LittleEndian.PutUint32(result[56:60], 2)
			copy(result[64:], "ok")
			binary.LittleEndian.PutUint32(length[:], uint32(len(result)))
			_, _ = conn.Write(append(length[:], result...))
			if !badNonce {
				var ack [1]byte
				_, err = io.ReadFull(conn, ack[:])
				if err == nil && ack[0] != 0xa5 {
					err = io.ErrUnexpectedEOF
				}
			}
			serverDone <- err
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		id := "0123456789abcdef01234567"
		backend := FirecrackerOSvBackend{Path: "/usr/bin/firecracker", OutputLimit: 16384}
		line, err := backend.Exchange(ctx, RunRequest{Entrypoint: "/task-probe.so", TimeoutMS: 1000, jobID: id}, workdir)
		if badNonce {
			if err == nil {
				t.Fatal("accepted mismatched nonce")
			}
		} else {
			if err != nil || !strings.HasPrefix(line, guestResultPrefix) {
				t.Fatalf("exchange failed: %v %s", err, line)
			}
			var envelope struct {
				JobID  string `json:"job_id"`
				Stdout string `json:"stdout"`
				OK     bool   `json:"ok"`
			}
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, guestResultPrefix)), &envelope); err != nil || envelope.JobID != id || envelope.Stdout != "ok" || !envelope.OK {
				t.Fatalf("bad envelope: %+v %v", envelope, err)
			}
		}
		if err := <-serverDone; err != nil {
			t.Fatal(err)
		}
	}
}

func TestOSvBackendStagesFixedAgentAndRequiresModuleAllowlist(t *testing.T) {
	config := Config{ArtifactRoot: t.TempDir(), Backend: "firecracker-osv", Jailer: &JailerConfig{}}
	config.ApplyDefaults()
	if err := config.Validate(); err == nil {
		t.Fatal("OSv backend accepted an implicit module allowlist")
	}
	config.AllowedEntrypoints = []string{"/task-probe.so"}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	config.Image.Format = "qcow2"
	if err := config.Validate(); err == nil {
		t.Fatal("OSv backend accepted qcow2 image for Firecracker")
	}
	config.Image.Format = "raw"
	config.ArtifactManifest = &ArtifactManifestConfig{Path: "manifest.json"}
	if err := config.Validate(); err == nil {
		t.Fatal("OSv diagnostic accepted an incomplete signed manifest")
	}
	config.ArtifactManifest.SignaturePath = "manifest.sig"
	config.ArtifactManifest.PublicKeyPath = "/fixture/public.key"
	config.ArtifactManifest.SBOMPath = "sbom.json"
	if err := config.Validate(); err != nil {
		t.Fatalf("OSv diagnostic rejected complete signed manifest: %v", err)
	}
	config.Production = true
	if err := config.Validate(); err == nil {
		t.Fatal("OSv production gate opened before full E2E review")
	}
	workdir := filepath.Join(t.TempDir(), "job-osv-a1b2")
	if err := os.Mkdir(workdir, 0o700); err != nil {
		t.Fatal(err)
	}
	kernel := filepath.Join(t.TempDir(), "kernel")
	image := filepath.Join(t.TempDir(), "image")
	if err := os.WriteFile(kernel, []byte("kernel"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(image, []byte("image"), 0o444); err != nil {
		t.Fatal(err)
	}
	backend := FirecrackerOSvBackend{Path: "/usr/local/bin/firecracker", Jailer: config.Jailer}
	request := RunRequest{Entrypoint: "/task-probe.so", Args: []string{"secret-argument"}, MemoryMiB: 128, VCPUs: 1}
	_, err := backend.Command(context.Background(), request,
		ResolvedArtifacts{KernelPath: kernel, ImagePath: image, Format: "raw"}, workdir)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := os.ReadFile(filepath.Join(workdir, "jailer/firecracker/job-osv-a1b2/root/config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(staged, []byte("/osv-job-agent.so")) ||
		!bytes.Contains(staged, []byte("\"uds_path\":\"/agent.vsock\"")) ||
		bytes.Contains(staged, []byte("secret-argument")) ||
		bytes.Contains(staged, []byte("/task-probe.so")) ||
		bytes.Contains(staged, []byte("network-interfaces")) {
		t.Fatalf("unsafe OSv launch config: %s", staged)
	}
}
