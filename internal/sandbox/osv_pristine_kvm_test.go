package sandbox

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This is signed-template protocol acceptance, before OSv pool integration.
func TestOSvPristinePreparationOnKVM(t *testing.T) {
	path := os.Getenv("OSV_NATIVE_PRISTINE_KVM_CONFIG")
	if path == "" {
		t.Skip("set OSV_NATIVE_PRISTINE_KVM_CONFIG to an isolated signed OSv fixture")
	}
	if os.Geteuid() != 0 || !strings.HasPrefix(path, "/var/lib/osv-offline-validation-") {
		t.Fatal("requires root and an isolated OSv fixture")
	}
	config, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.Production || config.Backend != "firecracker-osv" || config.Jailer == nil || config.WarmPool != nil {
		t.Fatal("requires diagnostic signed OSv, without a pool")
	}
	m, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	if !m.hasOSvAgentFeature("pristine-v1") {
		t.Fatal("signed template lacks pristine-v1")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := m.Shutdown(ctx); err != nil {
			t.Error(err)
		}
		if snapshot := m.Capacity(); snapshot.Active != 0 || snapshot.Instances != 0 || snapshot.Blocked {
			t.Errorf("diagnostic leaked resources: %+v", snapshot)
		}
	})
	boot := func(t *testing.T, pristine bool) (FirecrackerOSvBackend, *vmInstance, context.Context) {
		t.Helper()
		physical, active, err := m.reserveCold(128, 1)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		b := m.backend.(FirecrackerOSvBackend)
		b.Pristine = pristine
		request := RunRequest{MemoryMiB: 128, VCPUs: 1}
		if !pristine {
			request.Entrypoint = "/task-probe.so"
		}
		v, err := m.startVM(ctx, b, request, physical)
		t.Cleanup(func() {
			cancel()
			if v != nil {
				if err := v.Destroy(); err != nil {
					t.Error(err)
					return
				}
				if t.Failed() {
					t.Log("guest serial:", v.output.String())
				}
			}
			active.release()
		})
		if err != nil {
			t.Fatal(err)
		}
		return b, v, ctx
	}
	probe := func(t *testing.T, b FirecrackerOSvBackend, v *vmInstance, parent context.Context) {
		t.Helper()
		ctx, cancel := context.WithTimeout(parent, 10*time.Second)
		defer cancel()
		remaining, err := b.probePristine(ctx, v.workdir)
		if err != nil || remaining <= 10*time.Second || remaining > 600*time.Second {
			t.Fatalf("pristine probe failed: %v %v", remaining, err)
		}
	}
	binding := func(t *testing.T) osvPristineBinding {
		t.Helper()
		id, err := randomID()
		if err != nil {
			t.Fatal(err)
		}
		value, err := newOSvPristineBinding(id)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	exited := func(t *testing.T, v *vmInstance, parent context.Context) {
		t.Helper()
		select {
		case <-v.exited:
		case <-time.After(4 * time.Second):
			t.Fatal("guest did not power off")
		}
		var exit *exec.ExitError
		if err := v.waitError(); err != nil && (!errors.As(err, &exit) || exit.ExitCode() != 1) {
			t.Fatalf("guest exit was not normal Firecracker poweroff: %v", err)
		}
		if parent.Err() != nil {
			t.Fatal("host timeout, not guest, caused exit")
		}
	}
	job := func(value osvPristineBinding, argument string) RunRequest {
		return RunRequest{jobID: value.ID, Entrypoint: "/task-probe.so", Args: []string{argument}, TimeoutMS: 10000}
	}
	t.Run("unused-health-budget-and-bound-env-stdin", func(t *testing.T) {
		b, v, ctx := boot(t, true)
		for i := 0; i < 110; i++ {
			probe(t, b, v, ctx)
		}
		value := binding(t)
		if err := b.preparePristine(ctx, value, 10000, v.workdir); err != nil {
			t.Fatal(err)
		}
		request := job(value, "native-env-stdin")
		request.Environment = map[string]string{"SANDBOX_TEST_MARKER": "native-env-ok"}
		request.Stdin = []byte{'A', 0, 'B', 0xff, '\n'}
		line, err := b.exchangePrepared(ctx, request, value, v.workdir)
		if err != nil {
			t.Fatal(err)
		}
		data, protocolOK, guestOK := extractGuestResultFor(line, value.ID, guestResultPrefix, "osv-agent/v1")
		var envelope struct{ Stdout string }
		if json.Unmarshal(data, &envelope) != nil || !protocolOK || !guestOK || !strings.Contains(envelope.Stdout, "OSV_NATIVE_STDIN_BINARY_OK") {
			t.Fatal("bound module env/stdin/result failed")
		}
		exited(t, v, ctx)
	})
	for _, mode := range []string{"run-before-prepare", "duplicate-prepare", "ping-after-prepare", "wrong-id", "wrong-nonce"} {
		t.Run(mode, func(t *testing.T) {
			b, v, ctx := boot(t, true)
			probe(t, b, v, ctx)
			value := binding(t)
			if mode != "run-before-prepare" {
				if err := b.preparePristine(ctx, value, 10000, v.workdir); err != nil {
					t.Fatal(err)
				}
			}
			var err error
			switch mode {
			case "duplicate-prepare":
				err = b.preparePristine(ctx, binding(t), 10000, v.workdir)
			case "ping-after-prepare":
				_, err = b.probePristine(ctx, v.workdir)
			default:
				if mode == "wrong-id" {
					value.ID = binding(t).ID
				} else if mode == "wrong-nonce" {
					value.Nonce[0] ^= 1
				}
				_, err = b.exchangePrepared(ctx, job(value, "native-success"), value, v.workdir)
			}
			if err == nil {
				t.Fatal("unsafe operation succeeded")
			}
			exited(t, v, ctx)
		})
	}
	for _, mode := range []string{"prepared-idle-ttl", "running-module-ttl"} {
		t.Run(mode, func(t *testing.T) {
			b, v, ctx := boot(t, true)
			probe(t, b, v, ctx)
			value := binding(t)
			if err := b.preparePristine(ctx, value, 1000, v.workdir); err != nil {
				t.Fatal(err)
			}
			if mode == "running-module-ttl" {
				if _, err := b.exchangePrepared(ctx, job(value, "native-sleep"), value, v.workdir); err == nil {
					t.Fatal("long module completed despite guest TTL")
				}
			}
			exited(t, v, ctx)
		})
	}
	t.Run("legacy-job-still-executes", func(t *testing.T) {
		b, v, ctx := boot(t, false)
		value := binding(t)
		line, err := b.Exchange(ctx, job(value, "native-success"), v.workdir)
		if err != nil {
			t.Fatal(err)
		}
		_, protocolOK, guestOK := extractGuestResultFor(line, value.ID, guestResultPrefix, "osv-agent/v1")
		if !protocolOK || !guestOK {
			t.Fatal("legacy result failed")
		}
		exited(t, v, ctx)
	})
	t.Run("legacy-mode-cannot-prove-pristine", func(t *testing.T) {
		b, v, ctx := boot(t, false)
		b.Pristine = true // Probe an agent deliberately booted without the flag.
		if _, err := b.probePristine(ctx, v.workdir); err == nil {
			t.Fatal("legacy guest passed readiness")
		}
		exited(t, v, ctx)
	})
	for _, mode := range []string{"bad-magic", "reserved-bits", "invalid-id", "zero-nonce", "ping-with-ttl", "oversized", "lost-prepare-ack"} {
		t.Run(mode, func(t *testing.T) {
			b, v, ctx := boot(t, true)
			probe(t, b, v, ctx)
			request := osvPristineRequest{Operation: osvPristinePing, Binding: binding(t)}
			if mode == "lost-prepare-ack" {
				request.Operation, request.TTLMS = osvPristinePrepare, 10000
			}
			frame, err := encodeOSvPristineRequest(request)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "bad-magic":
				frame[4] ^= 1
			case "reserved-bits":
				frame[9] = 1
			case "invalid-id":
				frame[12] = 'A'
			case "zero-nonce":
				clear(frame[36:52])
			case "ping-with-ttl":
				binary.LittleEndian.PutUint32(frame[52:], 1000)
			case "oversized":
				binary.LittleEndian.PutUint32(frame, osvJobRequestMax+1)
				frame = frame[:4]
			}
			socket, err := jailedFirecrackerVsockPath(b.Path, v.workdir)
			if err != nil {
				t.Fatal(err)
			}
			conn, reader, stop, err := dialFirecrackerVsock(ctx, socket, osvJobPort)
			if err != nil {
				t.Fatal(err)
			}
			_, err = conn.Write(frame)
			if err == nil && mode == "lost-prepare-ack" {
				_, err = readOSvFrame(reader, osvPristineResponseLen)
			} else if err == nil {
				_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				_, err = io.Copy(io.Discard, reader)
			}
			stop()
			_ = conn.Close()
			if mode == "lost-prepare-ack" && err != nil {
				t.Fatal("prepare response missing before intentional lost ACK:", err)
			}
			exited(t, v, ctx)
		})
	}
	if paths, _ := filepath.Glob(filepath.Join(config.RunRoot, "job-*")); len(paths) != 0 {
		t.Fatal("protocol tests retained work directories", paths)
	}
}
