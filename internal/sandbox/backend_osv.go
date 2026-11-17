package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"time"
)

const osvJobPort = 5000

// FirecrackerOSvBackend boots a signed OSv image with one native job agent.
// The requested module and arguments travel over vsock, never boot args.
type FirecrackerOSvBackend struct {
	Path           string
	Jailer         *JailerConfig
	OutputLimit    int
	Pristine       bool
	ReadonlyInputs bool
	GuestProxy     bool
	ROFSCache      string
}

func (b FirecrackerOSvBackend) Name() string { return "firecracker-osv" }

func (b FirecrackerOSvBackend) ResultProtocol() (string, string) {
	return guestResultPrefix, "osv-agent/v1"
}

func (b FirecrackerOSvBackend) UsesControlChannel() bool { return true }

func (b FirecrackerOSvBackend) Command(ctx context.Context, req RunRequest, artifacts ResolvedArtifacts, workdir string) (*exec.Cmd, error) {
	if b.ReadonlyInputs && !b.Pristine {
		return nil, errors.New("OSv readonly inputs require explicit pristine preparation")
	}
	if req.Network == "proxy" && !b.GuestProxy {
		return nil, errors.New("OSv guest proxy requires its signed v7 profile")
	}
	if b.Jailer == nil || artifacts.Format != "raw" || (!b.Pristine && !validOSvModulePath(req.Entrypoint)) {
		return nil, errors.New("firecracker-osv requires jailer, raw image, and canonical module path")
	}
	bootArgs := "--nopci --console=serial --rootfs=rofs"
	if b.ROFSCache == "disabled" {
		bootArgs += " --disable_rofs_cache"
	} else if b.ROFSCache != "" {
		return nil, errors.New("unsupported OSv ROFS cache policy")
	}
	bootArgs += " /osv-job-agent.so"
	if b.Pristine {
		if req.Entrypoint != "" || len(req.Args) != 0 || len(req.Environment) != 0 || req.Stdin != nil || len(req.InputFiles) != 0 {
			return nil, errors.New("OSv pristine boot must not contain tenant payload")
		}
		if b.ReadonlyInputs {
			bootArgs += " --pristine-inputs-v1"
		} else {
			bootArgs += " --pristine-v1"
		}
	}
	instanceID := filepath.Base(workdir)
	if err := validateJailerID(instanceID); err != nil {
		return nil, err
	}
	config := map[string]any{
		"boot-source": map[string]any{
			"kernel_image_path": "/kernel",
			"boot_args":         bootArgs,
		},
		"drives": []map[string]any{{
			"drive_id": "rootfs", "path_on_host": "/rootfs",
			"is_root_device": true, "is_read_only": true,
		}},
		"vsock": map[string]any{
			"guest_cid": linuxGuestCID(instanceID), "uds_path": "/agent.vsock",
		},
		"machine-config": map[string]any{
			"vcpu_count": req.VCPUs, "mem_size_mib": req.MemoryMiB,
			"smt": false, "track_dirty_pages": false,
		},
	}
	data, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	return (FirecrackerBackend{Path: b.Path, Jailer: b.Jailer}).jailerCommand(ctx, req, artifacts, workdir, data)
}

func (b FirecrackerOSvBackend) Exchange(ctx context.Context, req RunRequest, workdir string) (string, error) {
	if b.Pristine {
		return "", errors.New("OSv pristine execution requires an explicit prepared binding")
	}
	if !canonicalJobID(req.jobID) {
		return "", errors.New("OSv exchange requires a canonical job id")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return b.exchangeJob(ctx, req, workdir, nonce)
}

func (b FirecrackerOSvBackend) exchangeJob(ctx context.Context, req RunRequest, workdir string, nonce [16]byte) (string, error) {
	limit := b.OutputLimit
	if limit < 16384 {
		return "", errors.New("OSv output budget must be at least 16384 bytes")
	}
	maxCapture := (limit - 4096) / 6
	if maxCapture < 1024 {
		maxCapture = 1024
	}
	if maxCapture > 1<<20 {
		maxCapture = 1 << 20
	}
	request, err := encodeOSvJobRequest(req, nonce, maxCapture)
	if err != nil {
		return "", err
	}
	socketPath, err := jailedFirecrackerVsockPath(b.Path, workdir)
	if err != nil {
		return "", err
	}
	conn, reader, stopClosing, err := dialFirecrackerVsock(ctx, socketPath, osvJobPort)
	if err != nil {
		return "", err
	}
	defer stopClosing()
	defer conn.Close()
	for len(request) > 0 {
		count, writeErr := conn.Write(request)
		if writeErr != nil {
			return "", fmt.Errorf("write OSv job: %w", writeErr)
		}
		if count == 0 {
			return "", io.ErrShortWrite
		}
		request = request[count:]
	}
	body, err := readOSvFrame(reader, osvJobResultLen+maxCapture)
	if err != nil {
		return "", fmt.Errorf("read OSv job result: %w", err)
	}
	result, err := decodeOSvJobResult(body, req.jobID, nonce, maxCapture)
	if err != nil {
		return "", err
	}
	if _, err := conn.Write([]byte{0xa5}); err != nil {
		return "", fmt.Errorf("acknowledge OSv job result: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		if err == nil {
			return "", errors.New("OSv guest sent bytes after its result")
		}
		return "", fmt.Errorf("OSv guest did not close result stream: %w", err)
	}
	ok := result.Status == 0 && result.ExitCode == 0
	errorMessage := ""
	if result.Status != 0 {
		errorMessage = "OSv module load failed"
	}
	envelope := struct {
		Protocol        string `json:"protocol"`
		JobID           string `json:"job_id"`
		OK              bool   `json:"ok"`
		ExitCode        int32  `json:"exit_code"`
		RunnerStatus    int32  `json:"runner_status"`
		Stdout          string `json:"stdout"`
		Stderr          string `json:"stderr"`
		OutputTruncated bool   `json:"output_truncated"`
		Error           string `json:"error,omitempty"`
	}{
		Protocol: "osv-agent/v1", JobID: req.jobID, OK: ok,
		ExitCode: result.ExitCode, RunnerStatus: result.Status,
		Stdout: string(result.Stdout), Stderr: string(result.Stderr),
		OutputTruncated: result.Flags != 0, Error: errorMessage,
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", err
	}
	return guestResultPrefix + string(encoded), nil
}
