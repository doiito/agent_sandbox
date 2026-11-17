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
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

type Manager struct {
	owner             *Manager
	catalog           *templateCatalog
	config            Config
	artifacts         ResolvedArtifacts
	backend           Backend
	capacity          *resourceLedger
	runRootLock       *os.File
	reconciledOrphans int
	manifest          *SignedArtifactManifest
	inferenceTenants  map[string]bool
	inferenceAuth     *Authenticator
	cleanupFailed     atomic.Bool
	vmMu              sync.Mutex
	vmClosing         bool
	instances         map[*vmInstance]struct{}
	sessionMu         sync.RWMutex
	ownedSessions     map[string]registeredSession
	pool              *warmPool
	preparedCold      *preparedColdRuntime
}

type jailIdentity struct{ uid, gid int }

func NewManager(config Config) (*Manager, error) {
	config = config.snapshot()
	config.ApplyDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	root, err := newManagerRuntime(config, nil)
	if err != nil {
		return nil, err
	}
	if len(config.Templates) == 0 {
		return root, nil
	}
	members := []*Manager{root}
	selectors := map[string]bool{root.config.Backend + ":" + root.manifest.digestSHA256: true}
	for _, item := range config.Templates {
		child, childErr := newManagerRuntime(config.forTemplate(item), root)
		if childErr != nil {
			if root.runRootLock != nil {
				_ = root.runRootLock.Close()
			}
			return nil, fmt.Errorf("template %s: %w", item.ID, childErr)
		}
		key := child.config.Backend + ":" + child.manifest.digestSHA256
		if selectors[key] {
			if root.runRootLock != nil {
				_ = root.runRootLock.Close()
			}
			return nil, errors.New("duplicate authenticated template selector")
		}
		selectors[key] = true
		members = append(members, child)
	}
	catalog := newTemplateCatalog(root, members)
	for _, member := range members {
		member.catalog = catalog
	}
	return root, nil
}

func newManagerRuntime(config Config, owner *Manager) (*Manager, error) {
	config = config.snapshot()
	config.ApplyDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	artifacts, err := ResolveArtifacts(config.ArtifactRoot, config.Kernel, config.Image)
	if err != nil {
		return nil, err
	}
	manifest, err := verifyArtifactManifest(config, artifacts)
	if err != nil {
		return nil, fmt.Errorf("verify signed artifact manifest: %w", err)
	}
	if manifest != nil && manifest.GuestInference != nil && manifest.GuestInference.Architecture != runtime.GOARCH {
		return nil, errors.New("signed guest inference architecture differs from host")
	}
	var inferenceTenants map[string]bool
	var inferenceAuth *Authenticator
	if signedRemoteInferenceFeature(config.Backend, manifest) {
		auth, err := LoadAuthenticator(config.AuthPolicyPath)
		if err != nil {
			return nil, errors.New("remote inference profile requires a valid root tenant policy")
		}
		inferenceAuth = auth
		inferenceTenants = make(map[string]bool)
		for _, tenant := range auth.tenants {
			inferenceTenants[tenant.policy.ID] = tenant.inference != nil
		}
	}
	if manifest != nil && config.Backend == "firecracker-linux" && slices.Contains(manifest.AgentFeatures, "workspace-watch-v1") && config.LinuxGuest.VsockPort == linuxWatchPort {
		return nil, errors.New("execution vsock port collides with workspace watch port")
	}
	if manifest != nil && config.Backend == "firecracker-linux" && slices.Contains(manifest.AgentFeatures, "port-forward-v1") && config.LinuxGuest.VsockPort == linuxPortServicePort {
		return nil, errors.New("execution vsock port collides with signed port relay")
	}
	if manifest != nil && config.Backend == "firecracker-linux" && slices.Contains(manifest.AgentFeatures, "vsock-proxy-v1") && config.LinuxGuest.VsockPort == guestProxyVsockPort {
		return nil, errors.New("execution vsock port collides with signed guest proxy")
	}
	if err := os.MkdirAll(config.RunRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create run root: %w", err)
	}
	if config.Production {
		if err := ValidateProductionHostPaths(config, artifacts); err != nil {
			return nil, err
		}
	} else if config.requiresOwnedRunRoot() {
		if os.Geteuid() != 0 {
			return nil, errors.New("jailed signed runtime requires a privileged owner")
		}
		if err := trustedManagedRunRootPath(config.RunRoot); err != nil {
			return nil, fmt.Errorf("untrusted managed run root: %w", err)
		}
	}
	var runRootLock *os.File
	var reconciledOrphans int
	if owner == nil {
		runRootLock, reconciledOrphans, err = claimManagedRunRoot(config)
		if err != nil {
			return nil, err
		}
	} else {
		runRootLock, reconciledOrphans = owner.runRootLock, owner.reconciledOrphans
	}
	if config.Production && config.Backend == "firecracker-linux" {
		artifacts.ScratchTemplatePath, err = buildScratchTemplate(config)
		if err != nil {
			if owner == nil && runRootLock != nil {
				_ = runRootLock.Close()
			}
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
	} else if config.Backend == "firecracker-osv" {
		rofsCache := ""
		if manifest != nil {
			rofsCache = manifest.OSvROFSCache
		}
		backend = FirecrackerOSvBackend{
			Path: config.HypervisorPath, Jailer: config.Jailer, OutputLimit: config.Limits.MaxOutputByte,
			ROFSCache: rofsCache,
		}
	} else {
		backend = QEMUBackend{Path: config.HypervisorPath}
	}
	m := &Manager{config: config, artifacts: artifacts, backend: backend, capacity: newResourceLedger(config), runRootLock: runRootLock, reconciledOrphans: reconciledOrphans, manifest: manifest, inferenceTenants: inferenceTenants}
	m.inferenceAuth = inferenceAuth
	m.owner = owner
	if owner != nil {
		m.capacity = owner.capacity
	}
	if m.hasLinuxProxyFeature() {
		linux := m.backend.(FirecrackerLinuxBackend)
		linux.GuestProxy = true
		m.backend = linux
	}
	if m.config.Backend == "firecracker-osv" && m.hasGuestProxyFeature() {
		osv := m.backend.(FirecrackerOSvBackend)
		osv.GuestProxy = true
		m.backend = osv
	}
	if m.hasOSvInputFeature() {
		osv := m.backend.(FirecrackerOSvBackend)
		osv.ReadonlyInputs = true
		m.backend = osv
	}
	if m.hasLinuxWatchFeature() {
		linux := m.backend.(FirecrackerLinuxBackend)
		linux.FileWatch = true
		m.backend = linux
	}
	if m.hasLinuxArtifactFeature() {
		linux := m.backend.(FirecrackerLinuxBackend)
		linux.WorkspaceArtifacts = true
		m.backend = linux
	}
	if m.hasLinuxPortFeature() {
		linux := m.backend.(FirecrackerLinuxBackend)
		linux.PortForward = true
		m.backend = linux
	}
	if err = m.enableLinuxCodeFeature(); err != nil {
		if owner == nil && runRootLock != nil {
			_ = runRootLock.Close()
		}
		return nil, err
	}
	if config.WarmPool != nil && config.WarmPool.Enabled {
		m.pool, err = newWarmPool(m)
		if err != nil {
			if owner == nil && runRootLock != nil {
				_ = runRootLock.Close()
			}
			return nil, err
		}
	}
	if m.pool == nil && m.hasOSvInputFeature() {
		m.preparedCold, err = newPreparedColdRuntime(m)
		if err != nil {
			if owner == nil && runRootLock != nil {
				_ = runRootLock.Close()
			}
			return nil, err
		}
	}
	return m, nil
}

func (m *Manager) Config() Config { return m.config.snapshot() }

func (m *Manager) Run(ctx context.Context, req RunRequest) (result RunResult, runErr error) {
	if m.catalog != nil && m.owner == nil {
		selected, err := m.selectTemplate(req.Backend, req.ArtifactManifestSHA256)
		if err != nil {
			return RunResult{}, err
		}
		if selected != m {
			return selected.Run(ctx, req)
		}
	}
	defer func() {
		if result.ID != "" && m.manifest != nil {
			result.ArtifactManifestSHA256 = m.manifest.digestSHA256
			if m.catalog != nil {
				result.TemplateID = m.config.defaultTemplateID()
			}
		}
	}()
	if m.cleanupFailed.Load() || m.isStopping() {
		return RunResult{}, fmt.Errorf("%w: prior job cleanup failed", ErrUnavailable)
	}
	if err := m.artifactAvailability(time.Now()); err != nil {
		return RunResult{}, err
	}
	if err := m.validateTemplateSelector(req); err != nil {
		return RunResult{}, err
	}
	req.Normalize(m.config)
	if err := req.Validate(m.config); err != nil {
		return RunResult{}, err
	}
	if req.Network == "proxy" && !m.hasGuestProxyFeature() {
		return RunResult{}, errors.New("network=proxy requires a supported signed guest proxy template")
	}
	if m.config.Backend == "firecracker-osv" && len(req.Environment) != 0 && !m.hasOSvAgentFeature("environment") {
		return RunResult{}, errors.New("environment requires a signed OSv agent feature")
	}
	if m.config.Backend == "firecracker-osv" && req.Stdin != nil && !m.hasOSvAgentFeature("stdin") {
		return RunResult{}, errors.New("stdin requires a signed OSv agent feature")
	}
	if m.config.Backend == "firecracker-osv" && len(req.InputFiles) != 0 && !m.hasOSvInputFeature() {
		return RunResult{}, errors.New("input files require signed OSv input-files-v1")
	}
	if m.pool != nil || m.preparedCold != nil {
		return m.runPreparedJob(ctx, req)
	}
	physical, active, err := m.reserveCold(req.MemoryMiB, req.VCPUs, ctx)
	if err != nil {
		return RunResult{}, err
	}
	var instance *vmInstance
	defer func() {
		if instance != nil {
			if cleanupErr := instance.Destroy(); cleanupErr != nil {
				result = RunResult{}
				runErr = errors.Join(runErr, cleanupErr)
				return
			}
		} else {
			physical.release()
		}
		active.release()
	}()
	id, err := randomID()
	if err != nil {
		return RunResult{}, err
	}

	// The control plane, not the caller, binds the guest result to this job.
	req.jobID = id
	transport, hasControlChannel := m.backend.(controlChannelBackend)
	if !hasControlChannel || !transport.UsesControlChannel() {
		req.Args = append([]string{"--sandbox-job-id", id}, req.Args...)
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(req.TimeoutMS)*time.Millisecond)
	defer cancel()
	instance, err = m.startVM(timeoutCtx, m.backend, req, physical)
	if err != nil {
		return RunResult{}, err
	}
	// A very short job can finish before this state update. Its completion is
	// still determined by the bound result and the one Wait watcher below.
	_ = instance.activate()
	workdir, out, started := instance.workdir, instance.output, instance.started

	type exchangeResult struct {
		line string
		err  error
	}
	var exchangeDone chan exchangeResult
	var cancelExchange context.CancelFunc
	if hasControlChannel && transport.UsesControlChannel() {
		var exchangeCtx context.Context
		exchangeCtx, cancelExchange = context.WithCancel(timeoutCtx)
		defer cancelExchange()
		exchangeDone = make(chan exchangeResult, 1)
		go func() {
			line, exchangeErr := transport.Exchange(exchangeCtx, req, workdir)
			exchangeDone <- exchangeResult{line: line, err: exchangeErr}
		}()
	}
	timedOut := false
	select {
	case <-instance.exited:
	case <-timeoutCtx.Done():
		timedOut = errors.Is(timeoutCtx.Err(), context.DeadlineExceeded)
		if err := instance.Destroy(); err != nil {
			return RunResult{}, err
		}
	}
	waitErr := instance.waitError()

	var exchange exchangeResult
	if exchangeDone != nil {
		// A VMM that exits before opening vsock must not leave the request
		// waiting for the full TTL. Allow a bounded drain after normal exit,
		// since result delivery and VMM shutdown can race on the host.
		drain := time.NewTimer(100 * time.Millisecond)
		select {
		case exchange = <-exchangeDone:
		case <-drain.C:
			cancelExchange()
			exchange = <-exchangeDone
		case <-timeoutCtx.Done():
			cancelExchange()
			exchange = <-exchangeDone
		}
		drain.Stop()
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
	cancelled := errors.Is(ctx.Err(), context.Canceled)
	if cancelled {
		state, exitCode = "cancelled", -1
	}
	prefix, protocol := guestResultPrefix, "osv-agent/v1"
	if provider, ok := m.backend.(resultProtocolBackend); ok {
		prefix, protocol = provider.ResultProtocol()
	}
	output := out.String()
	truncated := out.truncated
	resultSource := output
	if exchangeDone != nil {
		// Serial output is diagnostic only. It cannot forge completion or
		// consume the control channel's independent result storage budget.
		resultSource = ""
		combined := &limitedBuffer{limit: m.config.Limits.MaxOutputByte}
		if exchange.err == nil {
			resultSource = exchange.line
			_, _ = combined.Write([]byte(exchange.line + "\n"))
		} else {
			_, _ = combined.Write([]byte("CONTROL_CHANNEL_ERROR " + exchange.err.Error() + "\n"))
		}
		_, _ = combined.Write([]byte(output))
		output, truncated = combined.String(), truncated || combined.truncated
	}
	guestResult, protocolOK, guestOK := extractGuestResultFor(resultSource, id, prefix, protocol)
	if !timedOut && !cancelled && protocolOK && guestOK {
		// Firecracker --no-api reports the guest-triggered shutdown used by
		// one-shot OSv jobs as exit status 1. A valid job-bound guest envelope
		// is therefore the completion authority, not the VMM's raw exit code.
		state = "succeeded"
		exitCode = 0
	} else if !timedOut && !cancelled && protocolOK && !guestOK {
		var envelope struct {
			TimedOut bool `json:"timed_out"`
		}
		_ = json.Unmarshal(guestResult, &envelope)
		if envelope.TimedOut {
			state, exitCode, timedOut = "timed_out", -1, true
		} else {
			state = "guest_error"
			exitCode = guestFailureExitCode(guestResult)
		}
	} else if state == "succeeded" && !protocolOK {
		state = "protocol_error"
		exitCode = -1
	}
	return RunResult{
		ID: id, State: state, Backend: m.backend.Name(), ExitCode: exitCode,
		StartupMode: "cold",
		TimedOut:    timedOut, Duration: duration, DurationMS: duration.Milliseconds(),
		Output: output, OutputTruncated: truncated,
		ProtocolOK: protocolOK, GuestResult: guestResult,
	}, nil
}

// A bound guest exit code is authoritative; loader failures may have no
// task exit or report zero, which must still produce a nonzero failure code.
func guestFailureExitCode(raw json.RawMessage) int {
	var value struct {
		ExitCode *int `json:"exit_code"`
	}
	if json.Unmarshal(raw, &value) == nil && value.ExitCode != nil && *value.ExitCode != 0 {
		return *value.ExitCode
	}
	return 1
}

func (m *Manager) validateTemplateSelector(req RunRequest) error {
	if req.Backend == "" && req.ArtifactManifestSHA256 == "" {
		return nil
	}
	if req.Backend == "" || !validSHA256Hex(req.ArtifactManifestSHA256) {
		return ErrInvalidSelector
	}
	if m.manifest == nil || m.manifest.digestSHA256 == "" {
		return ErrUnavailable
	}
	if req.Backend != m.config.Backend || req.ArtifactManifestSHA256 != m.manifest.digestSHA256 {
		return ErrTemplateMismatch
	}
	return nil
}

func validSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
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
	instances := m.VMInstances()
	checks = append(checks, DoctorCheck{Name: "vm-lifecycle", OK: !instances.Stopping && !m.cleanupFailed.Load(),
		Detail: fmt.Sprintf("stopping=%t states=%v", instances.Stopping, instances.States)})
	var capacitySnapshot *VMCapacitySnapshot
	if m.capacity != nil {
		capacity := m.Capacity()
		capacitySnapshot = &capacity
		checks = append(checks, DoctorCheck{Name: "vm-capacity", OK: !capacity.Blocked, Detail: capacity.String()})
	}
	if m.manifest != nil || m.config.Production {
		check := DoctorCheck{Name: "signed-artifact-validity", OK: true, Detail: "authenticated startup manifest is within its admission window"}
		if err := m.artifactAvailability(time.Now()); err != nil {
			check.OK, check.Detail = false, err.Error()
		}
		checks = append(checks, check)
	}
	if m.config.requiresOwnedRunRoot() {
		owned := m.runRootLock != nil
		if owned {
			_, err := m.runRootLock.Stat()
			owned = err == nil
		}
		checks = append(checks, DoctorCheck{Name: "orphan-reconciliation", OK: owned, Detail: fmt.Sprintf("exclusive run_root lock held=%t; reconciled=%d", owned, m.reconciledOrphans)})
		cleanup := DoctorCheck{Name: "job-cleanup", OK: !m.cleanupFailed.Load(), Detail: "job workdir and cgroup cleanup is healthy"}
		if !cleanup.OK {
			cleanup.Detail = "prior job cleanup failed; stop and reconcile before restart"
		}
		checks = append(checks, cleanup)
	}
	if m.config.Production {
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
	if m.config.Backend == "firecracker" || m.config.Backend == "firecracker-linux" || m.config.Backend == "firecracker-osv" {
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
		} else if m.config.LinuxGuest.MkfsLoaderPath != "" {
			if _, err := exec.LookPath(m.config.LinuxGuest.MkfsLoaderPath); err != nil {
				checks = append(checks, DoctorCheck{Name: "mkfs", Detail: err.Error()})
			} else if info, err := os.Stat(m.config.LinuxGuest.MkfsLibraryPath); err != nil || !info.IsDir() {
				checks = append(checks, DoctorCheck{Name: "mkfs", Detail: "bundled mkfs library directory missing"})
			} else {
				checks = append(checks, DoctorCheck{Name: "mkfs", OK: true, Detail: "bundled loader and libraries"})
			}
		} else {
			checks = append(checks, DoctorCheck{Name: "mkfs", OK: true, Detail: m.config.LinuxGuest.MkfsPath})
		}
	}
	ready := true
	var warm *WarmPoolSnapshot
	if m.catalog != nil && m.owner == nil {
		for _, member := range m.catalog.members {
			err := member.artifactAvailability(time.Now())
			checks = append(checks, DoctorCheck{Name: "template:" + member.config.defaultTemplateID(), OK: err == nil, Detail: "authenticated template admission window"})
		}
	}
	if m.pool != nil || m.catalog != nil {
		value, _ := m.WarmPoolStatus()
		warm = &value
		if value.Enabled {
			checks = append(checks, DoctorCheck{Name: "warm-pool", OK: value.Healthy, Detail: fmt.Sprintf("running=%t degraded=%t foreground=%d", value.Running, value.Degraded, value.Foreground)})
		}
	}
	for _, check := range checks {
		if !check.OK && !check.Warning {
			ready = false
		}
	}
	return DoctorReport{Ready: ready, Checks: checks, VMCapacity: capacitySnapshot, VMInstances: &instances, WarmPool: warm}
}

func (m *Manager) artifactAvailability(now time.Time) error {
	if m.manifest == nil {
		if m.config.Production {
			return fmt.Errorf("%w: authenticated artifact manifest missing", ErrUnavailable)
		}
		return nil
	}
	if err := m.manifest.activeAt(now); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return nil
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
