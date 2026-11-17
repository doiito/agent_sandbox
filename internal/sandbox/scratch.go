package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func buildScratchTemplate(config Config) (string, error) {
	prefix := ".scratch-template-"
	if config.TemplateID != "" {
		prefix += config.TemplateID + "-"
	}
	path := filepath.Join(config.RunRoot, fmt.Sprintf("%s%d.ext4", prefix, config.LinuxGuest.ScratchMiB))
	temporary := path + ".new"
	_ = os.Remove(temporary)
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return "", fmt.Errorf("create scratch template: %w", err)
	}
	size := int64(config.LinuxGuest.ScratchMiB) * 1024 * 1024
	if err := file.Truncate(size); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := mkfsCommand(ctx, *config.LinuxGuest,
		"-q", "-F", "-O", "^has_journal", "-U", "00000000-0000-0000-0000-000000000001",
		"-L", "agent-scratch", temporary)
	if output, err := command.CombinedOutput(); err != nil {
		_ = os.Remove(temporary)
		return "", fmt.Errorf("format scratch template: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if err := os.Chmod(temporary, 0o400); err != nil {
		return "", err
	}
	if err := os.Rename(temporary, path); err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() != size {
		return "", fmt.Errorf("scratch template size is not %s bytes", strconv.FormatInt(size, 10))
	}
	return path, nil
}

func mkfsCommand(ctx context.Context, guest LinuxGuestConfig, args ...string) *exec.Cmd {
	if guest.MkfsLoaderPath == "" {
		return exec.CommandContext(ctx, guest.MkfsPath, args...)
	}
	loaderArgs := append([]string{"--library-path", guest.MkfsLibraryPath, guest.MkfsPath}, args...)
	return exec.CommandContext(ctx, guest.MkfsLoaderPath, loaderArgs...)
}
