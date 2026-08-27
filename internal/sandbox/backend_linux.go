package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	linuxGuestProtocol = "fc-agent/v1"
	linuxResultPrefix  = "FC_AGENT_RESULT "
)

// FirecrackerLinuxBackend boots a minimal Linux guest. Job arguments are not
// placed on the kernel command line; they are delivered to the Rust PID 1 over
// virtio-vsock after the VM has booted.
type FirecrackerLinuxBackend struct {
	Path            string
	Jailer          *JailerConfig
	Guest           LinuxGuestConfig
	OutputLimit     int
	ScratchTemplate string
}

func (b FirecrackerLinuxBackend) Name() string { return "firecracker-linux" }

func (b FirecrackerLinuxBackend) ResultProtocol() (string, string) {
	return linuxResultPrefix, linuxGuestProtocol
}

func (b FirecrackerLinuxBackend) UsesControlChannel() bool { return true }

func (b FirecrackerLinuxBackend) Command(ctx context.Context, req RunRequest, a ResolvedArtifacts, workdir string) (*exec.Cmd, error) {
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
				"init=/sbin/agent-init random.trust_cpu=on agent.vsock_port=" + strconv.FormatUint(uint64(b.Guest.VsockPort), 10),
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

func (b FirecrackerLinuxBackend) createInputImage(ctx context.Context, files []InputFile, imagePath, sourceRoot string) error {
	if err := os.MkdirAll(sourceRoot, 0o555); err != nil {
		return err
	}
	if err := os.Chmod(sourceRoot, 0o555); err != nil {
		return err
	}
	for _, input := range files {
		destination := filepath.Join(sourceRoot, input.Path)
		relative, err := filepath.Rel(sourceRoot, destination)
		if err != nil || strings.HasPrefix(relative, "..") {
			return errors.New("input file escaped staging root")
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o555); err != nil {
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
	file, err := os.OpenFile(imagePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o400)
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
	command := exec.CommandContext(ctx, b.Guest.MkfsPath, "-q", "-F", "-O", "^has_journal", "-d", sourceRoot, "-L", "agent-input", imagePath)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("format input image: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return os.Chmod(imagePath, 0o400)
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
	cmd := exec.CommandContext(ctx, b.Guest.MkfsPath, "-q", "-F", "-O", "^has_journal", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("format scratch image: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

type linuxJobRequest struct {
	Protocol       string   `json:"protocol"`
	JobID          string   `json:"job_id"`
	Argv           []string `json:"argv"`
	TimeoutMS      int      `json:"timeout_ms"`
	MaxOutputBytes int      `json:"max_output_bytes"`
}

func (b FirecrackerLinuxBackend) Exchange(ctx context.Context, req RunRequest, workdir string) (string, error) {
	if req.jobID == "" {
		return "", errors.New("Linux guest exchange is missing a job id")
	}
	socketPath, err := b.vsockPath(workdir)
	if err != nil {
		return "", err
	}
	socketDir, err := os.Open(filepath.Dir(socketPath))
	if err != nil {
		return "", fmt.Errorf("open jailed vsock directory: %w", err)
	}
	defer socketDir.Close()
	// sockaddr_un.sun_path is limited to 108 bytes. Per-job jail paths are
	// intentionally descriptive and can exceed that, so resolve the already
	// opened trusted directory through procfs and keep the actual dial path
	// short without changing the process-wide working directory.
	socketPath = fmt.Sprintf("/proc/self/fd/%d/%s", socketDir.Fd(), filepath.Base(socketPath))
	var conn net.Conn
	var reader *bufio.Reader
	dialer := net.Dialer{Timeout: 25 * time.Millisecond}
	for {
		conn, err = dialer.DialContext(ctx, "unix", socketPath)
		if err == nil {
			if deadline, ok := ctx.Deadline(); ok {
				_ = conn.SetDeadline(deadline)
			}
			reader = bufio.NewReaderSize(conn, b.outputLimit()+4096)
			if _, err = fmt.Fprintf(conn, "CONNECT %d\n", b.Guest.VsockPort); err == nil {
				var ack string
				ack, err = reader.ReadString('\n')
				if err == nil && strings.HasPrefix(ack, "OK ") {
					break
				}
				if err == nil {
					err = fmt.Errorf("unexpected guest vsock acknowledgement %q", strings.TrimSpace(ack))
				}
			}
			_ = conn.Close()
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("connect guest vsock: %w (last error: %v)", ctx.Err(), err)
		case <-time.After(2 * time.Millisecond):
		}
	}
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
	absoluteWorkdir, err := filepath.Abs(workdir)
	if err != nil {
		return "", err
	}
	instanceID := filepath.Base(absoluteWorkdir)
	return filepath.Join(absoluteWorkdir, "jailer", filepath.Base(b.Path), instanceID, "root", "agent.vsock"), nil
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
