package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// Only transport failures before any prepare payload write may carry this tag.
// A failed/partial payload write or a lost response always remains uncertain.
var errPristinePrepareNotSent = errors.New("pristine preparation was not sent")

// Binding secrets stay in memory; only ID is persisted with VM ownership.
type pristineBinding struct {
	ID    string
	nonce [32]byte
}

func newPristineBinding(id string) (pristineBinding, error) {
	b := pristineBinding{ID: id}
	if _, err := rand.Read(b.nonce[:]); err != nil {
		return pristineBinding{}, err
	}
	if !b.valid() {
		return pristineBinding{}, errors.New("invalid pristine binding")
	}
	return b, nil
}

func (b pristineBinding) valid() bool {
	return canonicalJobID(b.ID) && b.osv().Nonce != [16]byte{}
}

func (b pristineBinding) linux() linuxGuestBinding {
	return linuxGuestBinding{SessionID: b.ID, Nonce: hex.EncodeToString(b.nonce[:])}
}

func (b pristineBinding) osv() osvPristineBinding {
	value := osvPristineBinding{ID: b.ID}
	copy(value.Nonce[:], b.nonce[:16])
	return value
}

type pristinePreparation struct {
	Network    string
	Binding    pristineBinding
	Mode       string
	TTLMS      int
	InputFiles []InputFile
}

func (r pristinePreparation) validate() error {
	if r.Network != "" && r.Network != "none" && r.Network != "proxy" {
		return errors.New("invalid pristine network mode")
	}
	if !r.Binding.valid() || (r.Mode != "job" && r.Mode != "session") || r.TTLMS < 1000 || r.TTLMS > 300000 && (r.Mode != "session" || r.TTLMS > sessionMaxLifetimeMS) {
		return errors.New("invalid pristine preparation")
	}
	return validateInputFiles(r.InputFiles)
}

type pristineVMBackend interface {
	Backend
	resultProtocolBackend
	probeVM(context.Context, string) (time.Duration, error)
	prepareVM(context.Context, pristinePreparation, string) error
	runVM(context.Context, RunRequest, pristineBinding, string) (json.RawMessage, bool, error)
}

func pristineProtocolForBackend(backend string) string {
	switch backend {
	case "firecracker-linux":
		return "fc-agent/v3/pristine-revision-2"
	case "firecracker-osv":
		return "OSP1/revision-1/OSJ1"
	default:
		return "unsupported"
	}
}

func newPristineVMBackend(m *Manager) (pristineVMBackend, error) {
	if m.manifest == nil || !validSHA256Hex(m.manifest.digestSHA256) || m.backend == nil || m.backend.Name() != m.config.Backend {
		return nil, errors.New("warm pool requires an authenticated matching backend")
	}
	switch b := m.backend.(type) {
	case FirecrackerLinuxBackend:
		b.Pristine = true
		return linuxPristineVMBackend{b}, nil
	case FirecrackerOSvBackend:
		if (m.manifest.Protocol != "osv-sandbox-artifacts/v2" && m.manifest.Protocol != "osv-sandbox-artifacts/v7") || m.manifest.Backend != "firecracker-osv" || !m.hasOSvAgentFeature("pristine-v1") {
			return nil, errors.New("warm pool requires signed OSv pristine-v1 feature")
		}
		b.Pristine = true
		b.ReadonlyInputs = m.hasOSvInputFeature()
		return osvPristineVMBackend{b}, nil
	default:
		return nil, errors.New("backend has no pristine preparation driver")
	}
}

type linuxPristineVMBackend struct{ FirecrackerLinuxBackend }

func (b linuxPristineVMBackend) ResultProtocol() (string, string) {
	return linuxResultPrefix, linuxPristineProtocol
}

func (b linuxPristineVMBackend) probeVM(ctx context.Context, workdir string) (time.Duration, error) {
	return b.probeVMWithDial(ctx, workdir, dialFirecrackerVsock)
}

func (b linuxPristineVMBackend) probeVMWithDial(ctx context.Context, workdir string, dial firecrackerVsockDial) (time.Duration, error) {
	id, err := randomID()
	if err != nil {
		return 0, err
	}
	raw, ok, err := b.exchangeSession(ctx, linuxJobRequest{JobID: id, Operation: "ping", requireCodeReady: b.CodeContexts}, workdir, dial)
	if err != nil || !ok {
		return 0, errors.Join(err, errIfFalse(ok))
	}
	var result struct {
		Remaining     int `json:"remaining_lifetime_ms"`
		ProxyRevision int `json:"proxy_revision"`
	}
	if json.Unmarshal(raw, &result) != nil || result.Remaining <= 0 || result.Remaining > 600000 {
		return 0, ErrUnavailable
	}
	if b.GuestProxy && result.ProxyRevision != 1 {
		return 0, errors.New("signed guest proxy feature not proved by pristine guest")
	}
	return time.Duration(result.Remaining) * time.Millisecond, nil
}

func (b linuxPristineVMBackend) prepareVM(ctx context.Context, request pristinePreparation, workdir string) error {
	return b.prepareVMWithDial(ctx, request, workdir, dialFirecrackerVsock)
}

func (b linuxPristineVMBackend) prepareVMWithDial(ctx context.Context, request pristinePreparation, workdir string, dial firecrackerVsockDial) error {
	if err := request.validate(); err != nil {
		return err
	}
	id, err := randomID()
	if err != nil {
		return err
	}
	prepare := linuxPrepareRequest{Binding: request.Binding.linux(), Mode: request.Mode, TTLMS: request.TTLMS, InputFiles: request.InputFiles}
	if request.Network == "proxy" {
		prepare.Network = "proxy"
	}
	_, ok, err := b.exchangeSession(ctx, linuxJobRequest{JobID: id, Operation: "prepare", Prepare: &prepare}, workdir, dial)
	return errors.Join(err, errIfFalse(ok))
}

func (b linuxPristineVMBackend) runVM(ctx context.Context, request RunRequest, binding pristineBinding, workdir string) (json.RawMessage, bool, error) {
	if !binding.valid() || request.jobID != binding.ID {
		return nil, false, errors.New("prepared Linux execution binding mismatch")
	}
	value := binding.linux()
	return b.ExchangeSession(ctx, linuxJobRequest{JobID: request.jobID, Operation: "run", Binding: &value,
		Argv: append([]string{request.Entrypoint}, request.Args...), TimeoutMS: request.TimeoutMS,
		Environment: request.Environment, Cwd: request.Cwd, Stdin: request.Stdin}, workdir)
}

type osvPristineVMBackend struct{ FirecrackerOSvBackend }

func (b osvPristineVMBackend) probeVM(ctx context.Context, workdir string) (time.Duration, error) {
	return b.probePristine(ctx, workdir)
}

func (b osvPristineVMBackend) prepareVM(ctx context.Context, request pristinePreparation, workdir string) error {
	if err := request.validate(); err != nil {
		return err
	}
	if request.Mode != "job" || (len(request.InputFiles) != 0 && !b.ReadonlyInputs) {
		return errors.New("OSv pristine supports one-shot jobs; readonly inputs require signed input-files-v1")
	}
	if request.Network == "proxy" && !b.GuestProxy {
		return errors.New("OSv guest proxy requires its signed v7 profile")
	}
	return b.preparePristineInputs(ctx, request.Binding.osv(), request.TTLMS, request.InputFiles, workdir)
}

func (b osvPristineVMBackend) runVM(ctx context.Context, request RunRequest, binding pristineBinding, workdir string) (json.RawMessage, bool, error) {
	if !binding.valid() || request.jobID != binding.ID {
		return nil, false, errors.New("prepared OSv execution binding mismatch")
	}
	line, err := b.exchangePrepared(ctx, request, binding.osv(), workdir)
	if err != nil {
		return nil, false, err
	}
	prefix, protocol := b.ResultProtocol()
	raw, protocolOK, guestOK := extractGuestResultFor(line, binding.ID, prefix, protocol)
	if !protocolOK {
		return nil, false, errors.New("prepared OSv result is missing its bound envelope")
	}
	return raw, guestOK, nil
}
