package sandbox

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	linuxGuestProtocol    = "fc-agent/v1"
	linuxSessionProtocol  = "fc-agent/v2"
	linuxResultPrefix     = "FC_AGENT_RESULT "
	linuxJobStdinMaxBytes = 16 * 1024
	linuxWatchPort        = 5002
)

// FirecrackerLinuxBackend boots a minimal Linux guest. Job arguments are not
// placed on the kernel command line; they are delivered to the Rust PID 1 over
// virtio-vsock after the VM has booted.
type FirecrackerLinuxBackend struct {
	Path               string
	Jailer             *JailerConfig
	Guest              LinuxGuestConfig
	OutputLimit        int
	ScratchTemplate    string
	Pristine           bool
	GuestProxy         bool
	FileWatch          bool
	CodeContexts       bool
	CodePrewarm        string
	PortForward        bool
	WorkspaceArtifacts bool
}

func (b FirecrackerLinuxBackend) Name() string { return "firecracker-linux" }

func (b FirecrackerLinuxBackend) ResultProtocol() (string, string) {
	return linuxResultPrefix, linuxGuestProtocol
}

func (b FirecrackerLinuxBackend) UsesControlChannel() bool { return true }

func (b FirecrackerLinuxBackend) Command(ctx context.Context, req RunRequest, a ResolvedArtifacts, workdir string) (*exec.Cmd, error) {
	if req.Network == "proxy" && !b.GuestProxy {
		return nil, errors.New("guest proxy requires the signed backend feature")
	}
	if b.FileWatch && b.Guest.VsockPort == linuxWatchPort {
		return nil, errors.New("execution vsock port collides with the signed workspace watch port")
	}
	if b.CodeContexts && (b.Guest.VsockPort == linuxCodePort || !codeLanguage(b.CodePrewarm)) {
		return nil, errors.New("invalid signed code prewarm policy or colliding code control port")
	}
	if b.PortForward && b.Guest.VsockPort == linuxPortServicePort {
		return nil, errors.New("execution vsock port collides with the signed port relay service")
	}
	if b.WorkspaceArtifacts && b.Guest.VsockPort == linuxArtifactPort {
		return nil, errors.New("execution vsock port collides with the signed artifact service")
	}
	if b.Pristine && len(req.InputFiles) != 0 {
		return nil, errors.New("pristine boot must not contain tenant input")
	}
	if b.Pristine && req.Network == "proxy" {
		return nil, errors.New("pristine boot cannot contain tenant network permission")
	}
	if a.Format != "raw" {
		return nil, errors.New("firecracker-linux requires a raw rootfs image")
	}
	if b.Jailer == nil {
		return nil, errors.New("firecracker-linux requires jailer")
	}
	absoluteWorkdir, err := filepath.Abs(workdir)
	if err != nil {
		return nil, err
	}
	instanceID := filepath.Base(absoluteWorkdir)
	if err := validateJailerID(instanceID); err != nil {
		return nil, err
	}
	chrootBase := filepath.Join(absoluteWorkdir, "jailer")
	root := filepath.Join(chrootBase, filepath.Base(b.Path), instanceID, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("create Linux jail root: %w", err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		return nil, fmt.Errorf("set Linux jail root mode: %w", err)
	}
	if err := copyRegularFile(a.KernelPath, filepath.Join(root, "vmlinux"), 0o444); err != nil {
		return nil, fmt.Errorf("stage Linux kernel: %w", err)
	}
	if err := copyRegularFile(a.ImagePath, filepath.Join(root, "rootfs.ext4"), 0o444); err != nil {
		return nil, fmt.Errorf("stage Linux rootfs: %w", err)
	}
	scratchPath := filepath.Join(root, "scratch.ext4")
	if err := b.createScratch(ctx, scratchPath); err != nil {
		return nil, err
	}
	uid, gid := jailerIdentity(req, b.Jailer)
	if err := os.Chown(scratchPath, uid, gid); err != nil {
		return nil, fmt.Errorf("chown scratch image: %w", err)
	}
	inputPath := ""
	if len(req.InputFiles) > 0 {
		inputPath = filepath.Join(root, "input.ext4")
		if err := b.createInputImage(ctx, req.InputFiles, inputPath, filepath.Join(absoluteWorkdir, "input-root")); err != nil {
			return nil, err
		}
		if err := os.Chown(inputPath, uid, gid); err != nil {
			return nil, fmt.Errorf("chown input image: %w", err)
		}
	}

	drives := []map[string]any{
		{
			"drive_id": "rootfs", "path_on_host": "/rootfs.ext4",
			"is_root_device": true, "is_read_only": true,
		},
		{
			"drive_id": "scratch", "path_on_host": "/scratch.ext4",
			"is_root_device": false, "is_read_only": false,
		},
	}
	if inputPath != "" {
		drives = append(drives, map[string]any{
			"drive_id": "input", "path_on_host": "/input.ext4",
			"is_root_device": false, "is_read_only": true,
		})
	}
	fcConfig := map[string]any{
		"boot-source": map[string]any{
			"kernel_image_path": "/vmlinux",
			"boot_args": "console=ttyS0 reboot=k panic=1 pci=off quiet loglevel=3 root=/dev/vda ro " +
				"init=/sbin/agent-init random.trust_cpu=on i8042.nokbd=1 i8042.noaux=1 agent.vsock_port=" + strconv.FormatUint(uint64(b.Guest.VsockPort), 10),
		},
		"drives": drives,
		"vsock": map[string]any{
			"guest_cid": linuxGuestCID(instanceID), "uds_path": "/agent.vsock",
		},
		"machine-config": map[string]any{
			"vcpu_count": req.VCPUs, "mem_size_mib": req.MemoryMiB,
			"smt": false, "track_dirty_pages": false,
		},
	}
	if b.FileWatch {
		boot := fcConfig["boot-source"].(map[string]any)
		boot["boot_args"] = boot["boot_args"].(string) + " agent.watch=5002"
	}
	if b.WorkspaceArtifacts {
		boot := fcConfig["boot-source"].(map[string]any)
		boot["boot_args"] = boot["boot_args"].(string) + " agent.artifacts=5005"
	}
	if b.PortForward {
		boot := fcConfig["boot-source"].(map[string]any)
		boot["boot_args"] = boot["boot_args"].(string) + " agent.port=5004"
	}
	if b.CodeContexts {
		boot := fcConfig["boot-source"].(map[string]any)
		boot["boot_args"] = boot["boot_args"].(string) + " agent.code=5003 agent.code-prewarm=" + b.CodePrewarm
	}
	if b.Pristine {
		boot := fcConfig["boot-source"].(map[string]any)
		boot["boot_args"] = boot["boot_args"].(string) + " agent.pristine=1"
	} else if req.Network == "proxy" {
		boot := fcConfig["boot-source"].(map[string]any)
		boot["boot_args"] = boot["boot_args"].(string) + guestProxyBootArg(true)
	}
	data, err := json.Marshal(fcConfig)
	if err != nil {
		return nil, err
	}
	if err := writeFileExact(filepath.Join(root, "config.json"), data, 0o444); err != nil {
		return nil, fmt.Errorf("stage Linux Firecracker config: %w", err)
	}
	memoryMax := int64(req.MemoryMiB+b.Jailer.MemoryOverheadMiB) * 1024 * 1024
	args := []string{
		"--id", instanceID,
		"--exec-file", b.Path,
		"--uid", strconv.Itoa(uid),
		"--gid", strconv.Itoa(gid),
		"--chroot-base-dir", chrootBase,
		"--cgroup-version", strconv.Itoa(b.Jailer.CgroupVersion),
	}
	args = append(args, jailerResourceArgs(req, b.Jailer, memoryMax, absoluteWorkdir)...)
	args = append(args, "--", "--no-api", "--config-file", "/config.json")
	return exec.CommandContext(ctx, b.Jailer.Path, args...), nil
}

func (b FirecrackerLinuxBackend) createInputImage(ctx context.Context, files []InputFile, imagePath, sourceRoot string) (resultErr error) {
	if err := os.Mkdir(sourceRoot, 0o700); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, removeInputStaging(sourceRoot)) }()
	for _, input := range files {
		destination := filepath.Join(sourceRoot, input.Path)
		relative, err := filepath.Rel(sourceRoot, destination)
		if err != nil || strings.HasPrefix(relative, "..") {
			return errors.New("input file escaped staging root")
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return err
		}
		if err := writeFileExact(destination, input.Data, 0o444); err != nil {
			return err
		}
	}
	if err := filepath.WalkDir(sourceRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return os.Chmod(path, 0o555)
		}
		return nil
	}); err != nil {
		return err
	}
	file, err := os.OpenFile(imagePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := file.Truncate(int64(b.Guest.InputMiB) * 1024 * 1024); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	command := mkfsCommand(ctx, b.Guest, "-q", "-F", "-O", "^has_journal", "-d", sourceRoot, "-L", "agent-input", imagePath)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("format input image: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return os.Chmod(imagePath, 0o400)
}

func removeInputStaging(root string) error {
	// Export read-only directory modes into ext4, then restore owner write
	// permission for cleanup. This works without CAP_DAC_OVERRIDE too.
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.Chmod(path, 0o700)
		}
		return nil
	}); err != nil {
		return err
	}
	return os.RemoveAll(root)
}

func (b FirecrackerLinuxBackend) createScratch(ctx context.Context, path string) error {
	if b.ScratchTemplate != "" {
		if err := copyRegularFile(b.ScratchTemplate, path, 0o600); err != nil {
			return fmt.Errorf("clone scratch template: %w", err)
		}
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("create scratch image: %w", err)
	}
	size := int64(b.Guest.ScratchMiB) * 1024 * 1024
	err = f.Truncate(size)
	closeErr := f.Close()
	if err != nil {
		return fmt.Errorf("size scratch image: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close scratch image: %w", closeErr)
	}
	cmd := mkfsCommand(ctx, b.Guest, "-q", "-F", "-O", "^has_journal", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("format scratch image: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

type linuxJobRequest struct {
	requireCodeReady bool
	InteractiveStdin bool `json:"interactive_stdin,omitempty"`
	commandInput     <-chan linuxCommandInput
	onInputAck       func(linuxCommandInputAck) error
	Protocol         string               `json:"protocol"`
	JobID            string               `json:"job_id"`
	Operation        string               `json:"operation,omitempty"`
	Argv             []string             `json:"argv,omitempty"`
	TimeoutMS        int                  `json:"timeout_ms"`
	MaxOutputBytes   int                  `json:"max_output_bytes"`
	File             *SessionFileRequest  `json:"file,omitempty"`
	Binding          *linuxGuestBinding   `json:"binding,omitempty"`
	Prepare          *linuxPrepareRequest `json:"prepare,omitempty"`
	Environment      map[string]string    `json:"environment,omitempty"`
	Cwd              string               `json:"cwd,omitempty"`
	Stdin            []byte               `json:"stdin"`
	onOutput         func(SessionOutputEvent) error
	onStarted        func(int) error
	commandCancel    <-chan struct{}
}

// ExchangeSession performs one operation on a VM that remains alive after the
// response. The session owner serializes calls and closes the VM on transport
// errors, since a lost result cannot safely be retried.
func (b FirecrackerLinuxBackend) ExchangeSession(ctx context.Context, request linuxJobRequest, workdir string) (json.RawMessage, bool, error) {
	return b.exchangeSession(ctx, request, workdir, dialFirecrackerVsock)
}

// Transport selection happens after the same request validation, and before
// any payload write. Both fresh and preconnected channels share all framing,
// binding, cancellation, result and uncertain-send rules below.
func (b FirecrackerLinuxBackend) exchangeSession(ctx context.Context, request linuxJobRequest, workdir string, dial firecrackerVsockDial) (json.RawMessage, bool, error) {
	if request.InteractiveStdin && request.Operation != "run_stream" {
		return nil, false, errors.New("interactive stdin requires run_stream")
	}
	if request.JobID == "" || request.Operation == "" {
		return nil, false, errors.New("session exchange requires a job id and operation")
	}
	protocol := linuxSessionProtocol
	if b.Pristine {
		protocol = linuxPristineProtocol
		if request.Prepare != nil {
			if request.Operation != "prepare" || request.Binding != nil {
				return nil, false, errors.New("invalid preparation operation")
			}
			if err := request.Prepare.validate(); err != nil {
				return nil, false, err
			}
			prepared := *request.Prepare
			prepared.InputFiles = append([]InputFile(nil), prepared.InputFiles...)
			for i := range prepared.InputFiles {
				if prepared.InputFiles[i].Data == nil {
					prepared.InputFiles[i].Data = []byte{}
				}
			}
			request.Prepare = &prepared
		} else if request.Operation == "prepare" {
			return nil, false, errors.New("preparation body missing")
		}
		if request.Binding != nil && !request.Binding.valid() {
			return nil, false, errors.New("invalid prepared binding")
		}
	} else if request.Binding != nil || request.Prepare != nil {
		return nil, false, errors.New("legacy session does not accept preparation or binding")
	}
	request.Protocol = protocol
	if request.Operation == "run" || request.Operation == "run_stream" {
		request.MaxOutputBytes = b.guestOutputLimit()
		if request.Operation == "run_stream" && request.MaxOutputBytes > commandOutputLimit {
			request.MaxOutputBytes = commandOutputLimit
		}
	} else {
		request.Argv = nil
		request.TimeoutMS = 0
		request.MaxOutputBytes = 0
	}
	socketPath, err := b.vsockPath(workdir)
	if err != nil {
		if request.Prepare != nil {
			err = errors.Join(errPristinePrepareNotSent, err)
		}
		return nil, false, err
	}
	conn, reader, stopClosing, err := dial(ctx, socketPath, b.Guest.VsockPort)
	if err != nil {
		if request.Prepare != nil {
			err = errors.Join(errPristinePrepareNotSent, err)
		}
		return nil, false, err
	}
	defer stopClosing()
	defer conn.Close()
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, false, err
	}
	writer := bufio.NewWriter(conn)
	if _, err := writer.Write(payload); err != nil {
		return nil, false, fmt.Errorf("write session request: %w", err)
	}
	if err := writer.WriteByte('\n'); err != nil {
		return nil, false, fmt.Errorf("write session frame: %w", err)
	}
	if err := writer.Flush(); err != nil {
		return nil, false, fmt.Errorf("flush session request: %w", err)
	}
	stopControl := make(chan struct{})
	defer close(stopControl)
	var inputMu sync.Mutex
	var pendingInput *linuxCommandInput
	if request.Operation == "run_stream" {
		go func() {
			for {
				select {
				case <-stopControl:
					return
				case <-ctx.Done():
					return
				case <-request.commandCancel:
					_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
					if _, err := io.WriteString(conn, "cancel\n"); err != nil {
						_ = conn.Close()
					}
					return
				case input := <-request.commandInput:
					input.Protocol = protocol
					input.JobID = request.JobID
					input.Binding = request.Binding
					inputMu.Lock()
					pendingInput = &input
					inputMu.Unlock()
					encoded, err := json.Marshal(input)
					if err != nil {
						_ = conn.Close()
						return
					}
					_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
					_, err = conn.Write(append(encoded, '\n'))
					if err != nil {
						_ = conn.Close()
						return
					}
					_ = conn.SetWriteDeadline(time.Time{})
				}
			}
		}()
	}
	responseLimit := b.outputLimit()
	if request.Operation == "file" && responseLimit < 1<<20 {
		responseLimit = 1 << 20
	}
	var line string
	sequence, outputBytes := 0, 0
	started := false
	for {
		frame, err := readLauncherFrame(reader, responseLimit+4096)
		if err != nil {
			return nil, false, fmt.Errorf("read session result: %w", err)
		}
		line = string(frame)
		if strings.HasPrefix(line, "FC_AGENT_STDIN ") {
			var ack linuxCommandInputAck
			if !started || !request.InteractiveStdin || len(frame) > 1024 {
				return nil, false, errors.New("unexpected stdin ack")
			}
			if err := decodeLauncherFrame(frame[len("FC_AGENT_STDIN "):], &ack); err != nil {
				return nil, false, err
			}
			inputMu.Lock()
			pending := pendingInput
			pendingInput = nil
			inputMu.Unlock()
			if pending == nil || ack.Protocol != protocol || ack.JobID != request.JobID || !sameLinuxBinding(ack.Binding, request.Binding) || ack.Sequence != pending.Sequence || ack.WrittenBytes < 0 || ack.WrittenBytes > commandInputChunkLimit {
				return nil, false, errors.New("invalid stdin acknowledgement binding")
			}
			data, err := base64.StdEncoding.Strict().DecodeString(pending.DataBase64)
			if err != nil || ack.WrittenBytes > len(data) || ack.ErrorCode == nil && (ack.WrittenBytes != len(data) || ack.Closed != pending.Close) || ack.ErrorCode != nil && (*ack.ErrorCode != "stdin_closed" && *ack.ErrorCode != "stdin_io" && *ack.ErrorCode != "command_exited") {
				return nil, false, errors.New("invalid stdin acknowledgement result")
			}
			if request.onInputAck != nil {
				if err := request.onInputAck(ack); err != nil {
					return nil, false, err
				}
			}
			continue
		}
		if strings.HasPrefix(line, "FC_AGENT_STARTED ") {
			var start linuxCommandStarted
			if request.Operation != "run_stream" || started || sequence != 0 || len(frame) > 1024 {
				return nil, false, errors.New("unexpected command started frame")
			}
			if err := decodeLauncherFrame(frame[len("FC_AGENT_STARTED "):], &start); err != nil {
				return nil, false, err
			}
			if start.Protocol != protocol || start.JobID != request.JobID || start.PID <= 1 || start.PID > 1<<30 || !sameLinuxBinding(start.Binding, request.Binding) {
				return nil, false, errors.New("invalid command PID or started binding")
			}
			started = true
			if request.onStarted != nil {
				if err := request.onStarted(start.PID); err != nil {
					return nil, false, err
				}
			}
			continue
		}
		if !strings.HasPrefix(line, "FC_AGENT_EVENT ") {
			break
		}
		if request.Operation != "run_stream" || !started || len(frame) > 8192 {
			return nil, false, errors.New("unexpected command output frame")
		}
		var event linuxCommandOutput
		if err := decodeLauncherFrame(frame[len("FC_AGENT_EVENT "):], &event); err != nil {
			return nil, false, err
		}
		data, err := base64.StdEncoding.Strict().DecodeString(event.DataBase64)
		sequence++
		outputBytes += len(data)
		if err != nil || len(data) == 0 || len(data) > 4096 || base64.StdEncoding.EncodeToString(data) != event.DataBase64 ||
			event.Protocol != protocol || event.JobID != request.JobID || event.Sequence != sequence || sequence > 256 ||
			(event.Stream != "stdout" && event.Stream != "stderr") || outputBytes > request.MaxOutputBytes || !sameLinuxBinding(event.Binding, request.Binding) {
			return nil, false, errors.New("invalid command output event or binding")
		}
		if request.onOutput != nil {
			if err := request.onOutput(SessionOutputEvent{Sequence: event.Sequence, Stream: event.Stream, DataBase64: event.DataBase64}); err != nil {
				return nil, false, err
			}
		}
	}
	result, protocolOK, guestOK := extractGuestResultFor(line, request.JobID, linuxResultPrefix, protocol)
	if !protocolOK {
		return nil, false, errors.New("session result failed protocol or job ID binding")
	}
	if request.Operation == "run_stream" && guestOK && !started {
		return nil, false, errors.New("command ended without a bound started event")
	}
	if b.Pristine {
		if err := validatePreparedResult(request, result); err != nil {
			return nil, false, err
		}
	}
	if err := b.validateCodeReadiness(request, result); err != nil {
		return nil, false, err
	}
	if err := b.validatePortReadiness(request, result); err != nil {
		return nil, false, err
	}
	return result, guestOK, nil
}

func (b FirecrackerLinuxBackend) Exchange(ctx context.Context, req RunRequest, workdir string) (string, error) {
	if b.Pristine {
		return "", errors.New("pristine guest requires bound v3 preparation and execution")
	}
	if req.jobID == "" {
		return "", errors.New("Linux guest exchange is missing a job id")
	}
	socketPath, err := b.vsockPath(workdir)
	if err != nil {
		return "", err
	}
	conn, reader, stopClosing, err := dialFirecrackerVsock(ctx, socketPath, b.Guest.VsockPort)
	if err != nil {
		return "", err
	}
	defer stopClosing()
	defer conn.Close()
	guestTimeout := req.TimeoutMS
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline) - 100*time.Millisecond
		if remaining < time.Millisecond {
			remaining = time.Millisecond
		}
		if int(remaining.Milliseconds()) < guestTimeout {
			guestTimeout = int(remaining.Milliseconds())
		}
	}
	request := linuxJobRequest{
		Protocol: linuxGuestProtocol, JobID: req.jobID,
		Argv:      append([]string{req.Entrypoint}, req.Args...),
		TimeoutMS: guestTimeout, MaxOutputBytes: b.guestOutputLimit(),
		Environment: req.Environment, Cwd: req.Cwd, Stdin: req.Stdin,
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	if _, err := conn.Write(append(payload, '\n')); err != nil {
		return "", fmt.Errorf("write Linux guest job: %w", err)
	}
	limited := &io.LimitedReader{R: reader, N: int64(b.outputLimit() + 4096)}
	result, err := bufio.NewReader(limited).ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read Linux guest result: %w", err)
	}
	if !strings.HasPrefix(result, linuxResultPrefix) {
		return "", fmt.Errorf("unexpected Linux guest response prefix")
	}
	return strings.TrimSuffix(result, "\n"), nil
}

func (b FirecrackerLinuxBackend) outputLimit() int {
	if b.OutputLimit < 1024 {
		return 1 << 20
	}
	return b.OutputLimit
}

func (b FirecrackerLinuxBackend) guestOutputLimit() int {
	// stdout/stderr are embedded in a JSON result. Reserve envelope space and
	// account for the worst-case six-byte JSON escape of each captured byte so
	// the versioned result itself always fits the host output policy.
	limit := (b.outputLimit() - 4096) / 6
	if limit < 1024 {
		return 1024
	}
	return limit
}

func (b FirecrackerLinuxBackend) vsockPath(workdir string) (string, error) {
	return jailedFirecrackerVsockPath(b.Path, workdir)
}

func linuxGuestCID(instanceID string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(instanceID))
	// CID 0, 1 and 2 are reserved. Keep the high bit clear for compatibility.
	return 3 + h.Sum32()%0x7ffffffc
}

func validateJailerID(instanceID string) error {
	if instanceID == "" {
		return errors.New("empty jailer instance id")
	}
	for _, ch := range instanceID {
		if !(ch == '-' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9') {
			return fmt.Errorf("jailer instance id contains an unsupported character: %q", ch)
		}
	}
	return nil
}
