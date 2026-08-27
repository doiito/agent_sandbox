package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type Backend interface {
	Command(context.Context, RunRequest, ResolvedArtifacts, string) (*exec.Cmd, error)
	Name() string
}

type controlChannelBackend interface {
	Exchange(context.Context, RunRequest, string) (string, error)
	UsesControlChannel() bool
}

type resultProtocolBackend interface {
	ResultProtocol() (prefix string, protocol string)
}

type QEMUBackend struct{ Path string }

func (b QEMUBackend) Name() string { return "qemu" }

func (b QEMUBackend) Command(ctx context.Context, req RunRequest, a ResolvedArtifacts, _ string) (*exec.Cmd, error) {
	args, err := BuildQEMUArgs(req, a)
	if err != nil {
		return nil, err
	}
	return exec.CommandContext(ctx, b.Path, args...), nil
}

func BuildQEMUArgs(req RunRequest, a ResolvedArtifacts) ([]string, error) {
	if strings.Contains(a.ImagePath, ",") {
		return nil, errors.New("QEMU image paths may not contain commas")
	}
	guestArgs := append([]string{"--poweroff-after-result"}, req.Args...)
	cmdline, err := OSvCommandLine(req.Entrypoint, guestArgs)
	if err != nil {
		return nil, err
	}
	drive := fmt.Sprintf("file=%s,if=none,id=hd0,format=%s,readonly=on,cache=none", a.ImagePath, a.Format)
	return []string{
		"-m", strconv.Itoa(req.MemoryMiB) + "M",
		"-smp", strconv.Itoa(req.VCPUs),
		"-display", "none",
		"-monitor", "none",
		"-kernel", a.KernelPath,
		"-append", "--nopci --console=serial " + cmdline,
		"-M", "microvm,x-option-roms=off,pit=off,pic=off,rtc=off,auto-kernel-cmdline=on,acpi=off",
		"-nodefaults", "-no-user-config", "-no-reboot",
		"-global", "virtio-mmio.force-legacy=off",
		"-device", "virtio-blk-device,id=blk0,drive=hd0",
		"-drive", drive,
		"-nic", "none",
		"-enable-kvm", "-cpu", "host,+x2apic",
		"-serial", "stdio",
		"-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
	}, nil
}

type FirecrackerBackend struct {
	Path   string
	Jailer *JailerConfig
}

func (b FirecrackerBackend) Name() string { return "firecracker" }

func (b FirecrackerBackend) Command(ctx context.Context, req RunRequest, a ResolvedArtifacts, workdir string) (*exec.Cmd, error) {
	if a.Format != "raw" {
		return nil, errors.New("Firecracker requires a raw OSv image")
	}
	guestArgs := append([]string{"--poweroff-after-result"}, req.Args...)
	cmdline, err := OSvCommandLine(req.Entrypoint, guestArgs)
	if err != nil {
		return nil, err
	}
	kernelPath, imagePath := a.KernelPath, a.ImagePath
	if b.Jailer != nil {
		kernelPath, imagePath = "/kernel", "/rootfs"
	}
	fcConfig := map[string]any{
		"boot-source": map[string]any{
			"kernel_image_path": kernelPath,
			"boot_args":         "--nopci --console=serial " + cmdline,
		},
		"drives": []map[string]any{{
			"drive_id": "rootfs", "path_on_host": imagePath,
			"is_root_device": true, "is_read_only": true,
		}},
		"machine-config": map[string]any{
			"vcpu_count": req.VCPUs, "mem_size_mib": req.MemoryMiB,
			"smt": false, "track_dirty_pages": false,
		},
	}
	data, err := json.Marshal(fcConfig)
	if err != nil {
		return nil, err
	}
	if b.Jailer == nil {
		configPath := filepath.Join(workdir, "firecracker.json")
		if err := os.WriteFile(configPath, data, 0o600); err != nil {
			return nil, err
		}
		return exec.CommandContext(ctx, b.Path, "--no-api", "--config-file", configPath), nil
	}
	return b.jailerCommand(ctx, req, a, workdir, data)
}

func (b FirecrackerBackend) jailerCommand(ctx context.Context, req RunRequest, a ResolvedArtifacts, workdir string, config []byte) (*exec.Cmd, error) {
	absoluteWorkdir, err := filepath.Abs(workdir)
	if err != nil {
		return nil, err
	}
	instanceID := filepath.Base(absoluteWorkdir)
	for _, ch := range instanceID {
		if !(ch == '-' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9') {
			return nil, fmt.Errorf("jailer instance id contains an unsupported character: %q", ch)
		}
	}
	chrootBase := filepath.Join(absoluteWorkdir, "jailer")
	root := filepath.Join(chrootBase, filepath.Base(b.Path), instanceID, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("create jail root: %w", err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		return nil, fmt.Errorf("set jail root mode: %w", err)
	}
	if err := copyRegularFile(a.KernelPath, filepath.Join(root, "kernel"), 0o444); err != nil {
		return nil, fmt.Errorf("stage jailed kernel: %w", err)
	}
	if err := copyRegularFile(a.ImagePath, filepath.Join(root, "rootfs"), 0o444); err != nil {
		return nil, fmt.Errorf("stage jailed rootfs: %w", err)
	}
	if err := writeFileExact(filepath.Join(root, "config.json"), config, 0o444); err != nil {
		return nil, fmt.Errorf("stage jailed config: %w", err)
	}
	memoryMax := int64(req.MemoryMiB+b.Jailer.MemoryOverheadMiB) * 1024 * 1024
	uid, gid := jailerIdentity(req, b.Jailer)
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

func writeFileExact(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func jailerIdentity(req RunRequest, config *JailerConfig) (int, int) {
	if req.jailUID > 0 && req.jailGID > 0 {
		return req.jailUID, req.jailGID
	}
	return config.UID, config.GID
}

func jailerResourceArgs(req RunRequest, config *JailerConfig, memoryMax int64, workdir string) []string {
	cpuQuota := req.VCPUs * config.CPUQuotaPerVCPUUS
	args := []string{
		"--parent-cgroup", config.ParentCgroup,
		"--cgroup", "memory.max=" + strconv.FormatInt(memoryMax, 10),
		"--cgroup", "memory.swap.max=0",
		"--cgroup", "memory.oom.group=1",
		"--cgroup", fmt.Sprintf("cpu.max=%d %d", cpuQuota, config.CPUPeriodUS),
		"--cgroup", "pids.max=" + strconv.Itoa(config.PidsMax),
		"--resource-limit", "no-file=" + strconv.Itoa(config.NoFileLimit),
		"--resource-limit", "fsize=" + strconv.FormatInt(int64(config.FileSizeLimitMiB)*1024*1024, 10),
	}
	return args
}

func filesystemDevice(path string) (string, error) {
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return "", err
	}
	device := uint64(stat.Dev)
	major := (device >> 8) & 0xfff
	major |= (device >> 32) & ^uint64(0xfff)
	minor := device & 0xff
	minor |= (device >> 12) & ^uint64(0xff)
	deviceID := fmt.Sprintf("%d:%d", major, minor)
	// The cgroup v2 I/O controller accounts a partition's traffic against the
	// parent block device on common bare-metal layouts. Resolve that relation
	// through sysfs; device-mapper and whole-disk devices have no "partition"
	// marker and retain their own major:minor identifier.
	sysDevice, err := filepath.EvalSymlinks(filepath.Join("/sys/dev/block", deviceID))
	if err != nil {
		return deviceID, nil
	}
	if _, err := os.Stat(filepath.Join(sysDevice, "partition")); err != nil {
		return deviceID, nil
	}
	parentID, err := os.ReadFile(filepath.Join(filepath.Dir(sysDevice), "dev"))
	if err != nil {
		return "", err
	}
	resolved := strings.TrimSpace(string(parentID))
	if !validBlockDeviceID(resolved) {
		return "", fmt.Errorf("invalid parent block device %q", resolved)
	}
	return resolved, nil
}

func validBlockDeviceID(value string) bool {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}

func copyRegularFile(source, destination string, mode os.FileMode) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("source is not a regular file")
	}
	out, err := os.OpenFile(destination, os.O_RDWR|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	copyErr := cloneOrSparseCopy(out, in, info.Size())
	if copyErr == nil {
		copyErr = out.Chmod(mode)
	}
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

const ficlone = 0x40049409

func cloneOrSparseCopy(destination, source *os.File, size int64) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, destination.Fd(), ficlone, source.Fd())
	if errno == 0 {
		return nil
	}
	if err := destination.Truncate(size); err != nil {
		return err
	}
	const seekData, seekHole = 3, 4
	offset := int64(0)
	for offset < size {
		dataOffset, err := syscall.Seek(int(source.Fd()), offset, seekData)
		if err != nil {
			if errors.Is(err, syscall.ENXIO) {
				return nil
			}
			if _, seekErr := source.Seek(0, io.SeekStart); seekErr != nil {
				return seekErr
			}
			if _, seekErr := destination.Seek(0, io.SeekStart); seekErr != nil {
				return seekErr
			}
			_, err = io.Copy(destination, source)
			return err
		}
		holeOffset, err := syscall.Seek(int(source.Fd()), dataOffset, seekHole)
		if err != nil {
			return err
		}
		if _, err := source.Seek(dataOffset, io.SeekStart); err != nil {
			return err
		}
		if _, err := destination.Seek(dataOffset, io.SeekStart); err != nil {
			return err
		}
		if _, err := io.CopyN(destination, source, holeOffset-dataOffset); err != nil {
			return err
		}
		offset = holeOffset
	}
	return nil
}

func OSvCommandLine(entrypoint string, args []string) (string, error) {
	if entrypoint == "" {
		return "", errors.New("empty entrypoint")
	}
	tokens := append([]string{entrypoint}, args...)
	encoded := make([]string, 0, len(tokens))
	for _, token := range tokens {
		if strings.IndexByte(token, 0) >= 0 {
			return "", errors.New("NUL is not allowed in command arguments")
		}
		token = strings.ReplaceAll(token, `\`, `\\`)
		token = strings.ReplaceAll(token, `"`, `\"`)
		encoded = append(encoded, `"`+token+`"`)
	}
	return strings.Join(encoded, " "), nil
}
