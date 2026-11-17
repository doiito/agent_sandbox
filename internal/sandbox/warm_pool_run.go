package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

func (m *Manager) startPreparedSession(ctx context.Context, request SessionCreateRequest) (*Session, error) {
	backend, ok := m.pool.backend.(linuxPristineVMBackend)
	if !ok {
		return nil, errors.New("prepared sessions require the Linux backend")
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	lease, err := m.pool.acquire(ctx, request.MemoryMiB, request.VCPUs, request.TTLMS, "session", id, request.tenantID, request.InputFiles, request.startupStarted, request.Network)
	if err != nil {
		return nil, errors.Join(errUnavailableIfNotBusy(err), err)
	}
	expires := lease.leaseStart.Add(time.Duration(request.TTLMS) * time.Millisecond)
	sessionCtx, cancel := context.WithCancel(lease.instance.ctx)
	binding := lease.binding.linux()
	s := &Session{manager: m, backend: backend.FirecrackerLinuxBackend, info: SessionInfo{ID: id, State: "running", Backend: m.config.Backend, Network: request.Network,
		ArtifactManifestSHA256: request.ArtifactManifestSHA256, CreatedAt: lease.leaseStart.UTC(), ExpiresAt: expires.UTC(), StartupMode: lease.startupMode, StartupDurationUS: lease.startupUS,
		StartupTiming: lease.startupTiming, VMBootDurationUS: lease.vmBootUS,
		MemoryMiB: request.MemoryMiB, VCPUs: request.VCPUs, GuestProtocol: linuxPristineProtocol},
		workdir: lease.instance.workdir, memory: request.MemoryMiB, vcpus: request.VCPUs, instance: lease.instance, ctx: sessionCtx, cancel: cancel, active: lease.active, binding: &binding}
	s.startLeaseWatch(expires, lease.maxExpiresAt)

	if ctx.Err() != nil || sessionCtx.Err() != nil || lease.instance.ctx.Err() != nil {
		_ = s.Close()
		return nil, ErrSessionClosed
	}
	return s, nil
}

func errUnavailableIfNotBusy(err error) error {
	if errors.Is(err, ErrBusy) {
		return nil
	}
	return ErrUnavailable
}

func (m *Manager) runPreparedJob(parent context.Context, request RunRequest) (result RunResult, runErr error) {
	id, err := randomID()
	if err != nil {
		return RunResult{}, err
	}
	started := request.startupStarted
	if started.IsZero() {
		started = time.Now()
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(request.TimeoutMS)*time.Millisecond)
	defer cancel()
	var lease *preparedVM
	if m.pool != nil {
		lease, err = m.pool.acquire(ctx, request.MemoryMiB, request.VCPUs, max(1000, request.TimeoutMS), "job", id, request.tenantID, request.InputFiles, started, request.Network)
	} else {
		lease, err = m.preparedCold.acquire(ctx, request, id, started)
	}
	if err != nil {
		if contextErr := preparedJobContextError(ctx); contextErr != nil {
			state := "cancelled"
			if errors.Is(contextErr, context.DeadlineExceeded) {
				state = "timed_out"
			}
			return RunResult{ID: id, Backend: m.config.Backend, State: state, ExitCode: -1, TimedOut: state == "timed_out", Duration: time.Since(started), DurationMS: time.Since(started).Milliseconds()}, nil
		}
		return RunResult{}, errors.Join(errUnavailableIfNotBusy(err), err)
	}
	defer func() {
		if err := lease.close(); err != nil {
			result = RunResult{}
			runErr = errors.Join(runErr, err)
		}
	}()
	request.jobID = id
	raw, guestOK, exchangeErr := m.exchangePreparedJob(ctx, request, lease)
	state, exitCode, timedOut := "succeeded", 0, false
	var guest struct {
		ExitCode        int  `json:"exit_code"`
		TimedOut        bool `json:"timed_out"`
		OutputTruncated bool `json:"output_truncated"`
	}
	protocolOK := exchangeErr == nil && json.Unmarshal(raw, &guest) == nil
	contextErr := preparedJobContextError(ctx)
	switch {
	case errors.Is(contextErr, context.DeadlineExceeded):
		state, exitCode, timedOut = "timed_out", -1, true
	case parent.Err() != nil:
		state, exitCode = "cancelled", -1
	case !protocolOK:
		state, exitCode = "protocol_error", -1
	case guest.TimedOut:
		state, exitCode, timedOut = "timed_out", -1, true
	case !guestOK:
		state, exitCode = "guest_error", guestFailureExitCode(raw)
	default:
		exitCode = guest.ExitCode
	}
	if err := lease.close(); err != nil {
		return RunResult{}, err
	}
	output := &limitedBuffer{limit: m.config.Limits.MaxOutputByte}
	if protocolOK {
		prefix, _ := lease.backend.ResultProtocol()
		_, _ = output.Write([]byte(prefix + string(raw) + "\n"))
	} else {
		_, _ = output.Write([]byte(fmt.Sprintf("CONTROL_CHANNEL_ERROR %v\n", exchangeErr)))
	}
	_, _ = output.Write([]byte(lease.instance.output.String()))
	duration := time.Since(started)
	return RunResult{ID: id, State: state, Backend: m.config.Backend, ExitCode: exitCode, TimedOut: timedOut, Duration: duration, DurationMS: duration.Milliseconds(),
		Output: output.String(), OutputTruncated: output.truncated || guest.OutputTruncated, ProtocolOK: protocolOK, GuestResult: raw, StartupMode: lease.startupMode, StartupDurationUS: lease.startupUS,
		StartupTiming: lease.startupTiming, VMBootDurationUS: lease.vmBootUS}, nil
}

// The socket and context share an absolute deadline, but their timer callbacks
// need not run in the same order. Preserve cancellation already observed by
// the context and recognize elapsed deadlines before classifying I/O results.
func preparedJobContextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

// Delivery is independent of owner.ctx: guest poweroff may precede draining
// its valid result. Bound that drain so dead VMs never wait the entire job TTL.
func (m *Manager) exchangePreparedJob(ctx context.Context, request RunRequest, lease *preparedVM) (json.RawMessage, bool, error) {
	call, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		raw json.RawMessage
		ok  bool
		err error
	}
	done := make(chan result, 1)
	go func() {
		raw, ok, err := lease.backend.runVM(call, request, lease.binding, lease.instance.workdir)
		done <- result{raw, ok, err}
	}()
	var value result
	select {
	case value = <-done:
	case <-lease.instance.exited:
		drain := time.NewTimer(100 * time.Millisecond)
		defer drain.Stop()
		select {
		case value = <-done:
		case <-drain.C:
			cancel()
			value = <-done
		case <-ctx.Done():
			cancel()
			value = <-done
		}
	case <-ctx.Done():
		cancel()
		value = <-done
	}
	return value.raw, value.ok, value.err
}
