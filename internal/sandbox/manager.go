package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type Manager struct {
	config            Config
	artifacts         ResolvedArtifacts
	backend           Backend
	sem               chan struct{}
	identities        chan jailIdentity
	runRootLock       *os.File
	reconciledOrphans int
}

type jailIdentity struct{ uid, gid int }

func NewManager(config Config) (*Manager, error) {
	config.ApplyDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	artifacts, err := ResolveArtifacts(config.ArtifactRoot, config.Kernel, config.Image)
	if err != nil {
		return nil, err
	}
	if err := VerifyArtifactManifest(config, artifacts); err != nil {
		return nil, fmt.Errorf("verify signed artifact manifest: %w", err)
	}
	if err := os.MkdirAll(config.RunRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create run root: %w", err)
	}
	if config.Production {
		if err := ValidateProductionHostPaths(config, artifacts); err != nil {
			return nil, err
		}
	}
	var runRootLock *os.File
	reconciledOrphans := 0
	if config.Production {
		runRootLock, err = acquireRunRootLock(config.RunRoot)
		if err != nil {
			return nil, err
		}
		cgroupParent := ""
		if config.Jailer != nil {
			cgroupParent = config.Jailer.ParentCgroup
		}
		reconciledOrphans, err = reconcileRunRoot(config.RunRoot, cgroupParent)
		if err != nil {
			_ = runRootLock.Close()
			return nil, err
		}
		artifacts.ScratchTemplatePath, err = buildScratchTemplate(config)
		if err != nil {
			_ = runRootLock.Close()
			return nil, err
		}
	}
	var backend Backend
	if config.Backend == "firecracker" {
		backend = FirecrackerBackend{Path: config.HypervisorPath, Jailer: config.Jailer}
	} else if config.Backend == "firecracker-linux" {
		backend = FirecrackerLinuxBackend{
			Path: config.HypervisorPath, Jailer: config.Jailer,
			Guest: *config.LinuxGuest, OutputLimit: config.Limits.MaxOutputByte, ScratchTemplate: artifacts.ScratchTemplatePath,
		}
	} else {
		backend = QEMUBackend{Path: config.HypervisorPath}
	}
	m := &Manager{config: config, artifacts: artifacts, backend: backend, sem: make(chan struct{}, config.Limits.MaxConcurrent), runRootLock: runRootLock, reconciledOrphans: reconciledOrphans}
	if config.Jailer != nil && config.Jailer.IdentityPoolSize > 0 {
		m.identities = make(chan jailIdentity, config.Jailer.IdentityPoolSize)
		for offset := 0; offset < config.Jailer.IdentityPoolSize; offset++ {
			m.identities <- jailIdentity{uid: config.Jailer.UID + offset, gid: config.Jailer.GID + offset}
		}
	}
	return m, nil
}

func (m *Manager) Config() Config { return m.config }

func (m *Manager) Run(ctx context.Context, req RunRequest) (RunResult, error) {
	req.Normalize(m.config)
	if err := req.Validate(m.config); err != nil {
		return RunResult{}, err
	}
	select {
	case m.sem <- struct{}{}:
		defer func() { <-m.sem }()
	default:
		return RunResult{}, ErrBusy
	}
	if m.identities != nil {
		identity := <-m.identities
		req.jailUID, req.jailGID = identity.uid, identity.gid
		defer func() { m.identities <- identity }()
	}
	id, err := randomID()
	if err != nil {
		return RunResult{}, err
	}
	workdir, err := os.MkdirTemp(m.config.RunRoot, "job-"+id+"-")
	if err != nil {
		return RunResult{}, err
	}
	defer os.RemoveAll(workdir)
	if m.config.Jailer != nil {
		defer cleanupCgroup(m.config.Jailer.ParentCgroup, filepath.Base(workdir))
	}

	// The control plane, not the caller, binds the guest result to this job.
	req.jobID = id
	transport, hasControlChannel := m.backend.(controlChannelBackend)
	if !hasControlChannel || !transport.UsesControlChannel() {
		req.Args = append([]string{"--sandbox-job-id", id}, req.Args...)
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(req.TimeoutMS)*time.Millisecond)
	defer cancel()
	cmd, err := m.backend.Command(timeoutCtx, req, m.artifacts, workdir)
	if err != nil {
		return RunResult{}, err
	}
	if m.config.Jailer != nil {
		if err := prepareJobCgroup(*m.config.Jailer, filepath.Base(workdir), workdir); err != nil {
			return RunResult{}, fmt.Errorf("prepare job cgroup: %w", err)
		}
	}
	cmd.Dir = workdir
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	out := &limitedBuffer{limit: m.config.Limits.MaxOutputByte}
	cmd.Stdout, cmd.Stderr = out, out
	started := time.Now()
	if err := cmd.Start(); err != nil {
		return RunResult{}, fmt.Errorf("start %s: %w", m.backend.Name(), err)
	}
	if err := writeProcessLease(workdir, cmd.Process.Pid); err != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_, _ = cmd.Process.Wait()
		return RunResult{}, fmt.Errorf("persist VMM lease: %w", err)
	}
	if m.config.Jailer != nil {
		cgroupPath := filepath.Join("/sys/fs/cgroup", m.config.Jailer.ParentCgroup, filepath.Base(workdir))
		go moveKVMPITThread(timeoutCtx.Done(), cmd.Process.Pid, cgroupPath)
	}
	var exchangeDone chan error
	var cancelExchange context.CancelFunc
	if hasControlChannel && transport.UsesControlChannel() {
		var exchangeCtx context.Context
		exchangeCtx, cancelExchange = context.WithCancel(timeoutCtx)
		defer cancelExchange()
		exchangeDone = make(chan error, 1)
		go func() {
			line, exchangeErr := transport.Exchange(exchangeCtx, req, workdir)
			if line != "" {
				_, _ = out.Write([]byte(line + "\n"))
			}
			if exchangeErr != nil {
				_, _ = out.Write([]byte("CONTROL_CHANNEL_ERROR " + exchangeErr.Error() + "\n"))
			}
			exchangeDone <- exchangeErr
		}()
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var waitErr error
	timedOut := false
	select {
	case waitErr = <-done:
	case <-timeoutCtx.Done():
		timedOut = errors.Is(timeoutCtx.Err(), context.DeadlineExceeded)
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		waitErr = <-done
	}
	if exchangeDone != nil {
		// A VMM that exits before opening vsock must not leave the request
		// waiting until its full deadline just for the connector retry loop.
		cancelExchange()
		select {
		case <-exchangeDone:
		case <-timeoutCtx.Done():
		}
	}
	duration := time.Since(started)
	exitCode := 0
	state := "succeeded"
	if waitErr != nil {
		state = "failed"
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	if timedOut {
		state, exitCode = "timed_out", -1
	}
	prefix, protocol := guestResultPrefix, "osv-agent/v1"
	if provider, ok := m.backend.(resultProtocolBackend); ok {
		prefix, protocol = provider.ResultProtocol()
	}
	guestResult, protocolOK, guestOK := extractGuestResultFor(out.String(), id, prefix, protocol)
	if !timedOut && protocolOK && guestOK {
		// Firecracker --no-api reports the guest-triggered shutdown used by
		// one-shot OSv jobs as exit status 1. A valid job-bound guest envelope
		// is therefore the completion authority, not the VMM's raw exit code.
		state = "succeeded"
		exitCode = 0
	} else if !timedOut && protocolOK && !guestOK {
		var envelope struct {
			TimedOut bool `json:"timed_out"`
		}
		_ = json.Unmarshal(guestResult, &envelope)
		if envelope.TimedOut {
			state, exitCode, timedOut = "timed_out", -1, true
		} else {
			state = "guest_error"
			exitCode = 1
		}
	} else if state == "succeeded" && !protocolOK {
		state = "protocol_error"
		exitCode = -1
	}
	return RunResult{
		ID: id, State: state, Backend: m.backend.Name(), ExitCode: exitCode,
		TimedOut: timedOut, Duration: duration, DurationMS: duration.Milliseconds(),
		Output: out.String(), OutputTruncated: out.truncated,
		ProtocolOK: protocolOK, GuestResult: guestResult,
	}, nil
}

const guestResultPrefix = "OSV_AGENT_RESULT "

func extractGuestResult(output, expectedJobID string) (json.RawMessage, bool, bool) {
	return extractGuestResultFor(output, expectedJobID, guestResultPrefix, "osv-agent/v1")
}

func extractGuestResultFor(output, expectedJobID, prefix, protocol string) (json.RawMessage, bool, bool) {
	var found json.RawMessage
	guestOK := false
	for _, line := range bytes.Split([]byte(output), []byte{'\n'}) {
		if !bytes.HasPrefix(line, []byte(prefix)) {
			continue
		}
		candidate := bytes.TrimPrefix(line, []byte(prefix))
		var envelope struct {
			Protocol string `json:"protocol"`
			JobID    string `json:"job_id"`
			OK       *bool  `json:"ok"`
		}
		if json.Unmarshal(candidate, &envelope) == nil && envelope.Protocol == protocol && envelope.JobID == expectedJobID && envelope.OK != nil {
			found = append(found[:0], candidate...)
			guestOK = *envelope.OK
		}
	}
	return found, found != nil, guestOK
}

func (m *Manager) Doctor() DoctorReport {
	checks := []DoctorCheck{
		{Name: "artifacts", OK: true, Detail: "kernel and image paths are confined and SHA-256 verified"},
	}
	if m.config.Production {
		checks = append(checks, DoctorCheck{Name: "orphan-reconciliation", OK: true, Detail: fmt.Sprintf("exclusive run_root lock held; reconciled=%d", m.reconciledOrphans)})
		checks = append(checks, productionDoctorChecks(m.config)...)
	}
	if _, err := exec.LookPath(m.config.HypervisorPath); err != nil {
		checks = append(checks, DoctorCheck{Name: "hypervisor", Detail: err.Error()})
	} else {
		checks = append(checks, DoctorCheck{Name: "hypervisor", OK: true, Detail: m.config.HypervisorPath})
	}
	if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err != nil {
		checks = append(checks, DoctorCheck{Name: "kvm", Detail: err.Error()})
	} else {
		_ = f.Close()
		checks = append(checks, DoctorCheck{Name: "kvm", OK: true, Detail: "/dev/kvm is readable and writable"})
	}
	if m.config.Backend == "firecracker" || m.config.Backend == "firecracker-linux" {
		if m.config.Jailer == nil {
			checks = append(checks, DoctorCheck{Name: "jailer", OK: true, Warning: true, Detail: "disabled; direct Firecracker is intended only as a performance baseline"})
		} else if _, err := exec.LookPath(m.config.Jailer.Path); err != nil {
			checks = append(checks, DoctorCheck{Name: "jailer", Detail: err.Error()})
		} else if os.Geteuid() != 0 {
			checks = append(checks, DoctorCheck{Name: "jailer", Detail: "jailer mode requires the control-plane service to start as root; the VMM drops to the configured uid/gid"})
		} else {
			detail := fmt.Sprintf("%s; uid=%d gid=%d cgroup=v2 parent=%s", m.config.Jailer.Path, m.config.Jailer.UID, m.config.Jailer.GID, m.config.Jailer.ParentCgroup)
			if m.config.Jailer.IdentityPoolSize > 0 {
				detail += fmt.Sprintf(" identity-pool=%d", m.config.Jailer.IdentityPoolSize)
			}
			checks = append(checks, DoctorCheck{Name: "jailer", OK: true, Detail: detail})
		}
	}
	if m.config.Backend == "firecracker-linux" {
		if _, err := exec.LookPath(m.config.LinuxGuest.MkfsPath); err != nil {
			checks = append(checks, DoctorCheck{Name: "mkfs", Detail: err.Error()})
		} else {
			checks = append(checks, DoctorCheck{Name: "mkfs", OK: true, Detail: m.config.LinuxGuest.MkfsPath})
		}
	}
	ready := true
	for _, check := range checks {
		if !check.OK && !check.Warning {
			ready = false
		}
	}
	return DoctorReport{Ready: ready, Checks: checks}
}

func randomID() (string, error) {
	b := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

type limitedBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	original := len(p)
	remaining := b.limit - b.buf.Len()
	if remaining <= 0 {
		b.truncated = true
		return original, nil
	}
	if len(p) > remaining {
		p = p[:remaining]
		b.truncated = true
	}
	_, _ = b.buf.Write(p)
	return original, nil
}

func (b *limitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
