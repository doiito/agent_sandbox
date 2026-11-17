package offlinebundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

type SwitchOptions struct {
	Archive            string
	PublicKey          ed25519.PublicKey
	Root               string
	RunRoot            string
	CgroupRoot         string
	AllowTestCandidate bool
	CheckServices      func() error
}

type SwitchResult struct {
	Active   string
	Previous string
	Changed  bool
}

// Switch rechecks the signed archive and installed bytes before atomically
// selecting a version. It does not start or stop any service.
func Switch(options SwitchOptions) (SwitchResult, error) {
	var result SwitchResult
	if runtime.GOOS != "linux" || options.CheckServices == nil ||
		!filepath.IsAbs(options.Root) || !filepath.IsAbs(options.RunRoot) || !filepath.IsAbs(options.CgroupRoot) {
		return result, errors.New("switch requires Linux, absolute roots and a service quiescence check")
	}
	archive, err := os.Open(options.Archive)
	if err != nil {
		return result, err
	}
	manifest, verifyErr := Verify(archive, options.PublicKey, runtime.GOARCH, "")
	closeErr := archive.Close()
	if verifyErr != nil {
		return result, verifyErr
	}
	if closeErr != nil {
		return result, closeErr
	}
	if strings.HasSuffix(manifest.Commit, "-dirty-test") {
		if !options.AllowTestCandidate || !strings.HasPrefix(filepath.Base(filepath.Clean(options.Root)), "osv-offline-validation-") {
			return result, errors.New("test-signed dirty candidate requires an isolated validation root and explicit allowance")
		}
	}
	root := filepath.Clean(options.Root)
	releases := filepath.Join(root, "releases")
	for _, directory := range []string{root, releases, options.RunRoot} {
		if err := ownedDirectory(directory); err != nil {
			return result, err
		}
	}
	lock, err := os.OpenFile(filepath.Join(options.RunRoot, ".launcher.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return result, fmt.Errorf("open launcher lock: %w", err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return result, errors.New("launcher owns run_root; stop it before switching")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if err := options.CheckServices(); err != nil {
		return result, err
	}
	for _, directory := range []string{options.RunRoot, options.CgroupRoot} {
		if err := noJobEntries(directory); err != nil {
			return result, err
		}
	}
	name := manifest.Version + "-linux-" + manifest.Arch
	target := filepath.Join(releases, name)
	if err := verifyInstalled(target, manifest); err != nil {
		return result, err
	}
	selected := filepath.Join("releases", name)
	current := filepath.Join(root, "current")
	previous, err := currentRelease(current, manifest.Arch)
	if err != nil {
		return result, err
	}
	result = SwitchResult{Active: selected, Previous: previous, Changed: previous != selected}
	if !result.Changed {
		return result, nil
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return SwitchResult{}, err
	}
	temporary := filepath.Join(root, ".current-next-"+hex.EncodeToString(nonce[:]))
	if err := os.Symlink(selected, temporary); err != nil {
		return SwitchResult{}, err
	}
	defer os.Remove(temporary)
	if err := os.Rename(temporary, current); err != nil {
		return SwitchResult{}, err
	}
	dir, err := os.Open(root)
	if err != nil {
		return result, fmt.Errorf("current switched but cannot open deployment root for sync: %w", err)
	}
	syncErr := dir.Sync()
	closeErr = dir.Close()
	if syncErr != nil {
		return result, fmt.Errorf("current switched but deployment root sync failed: %w", syncErr)
	}
	if closeErr != nil {
		return result, fmt.Errorf("current switched but deployment root close failed: %w", closeErr)
	}
	return result, nil
}

func ownedDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("unsafe directory: %s", directory)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("directory is not owned by operator: %s", directory)
	}
	return nil
}

func noJobEntries(directory string) error {
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("unsafe job directory: %s", directory)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "job-") {
			return fmt.Errorf("job resource remains under %s", directory)
		}
	}
	return nil
}

func verifyInstalled(root string, manifest Manifest) error {
	if err := ownedDirectory(root); err != nil {
		return err
	}
	expected := make(map[string]File, len(manifest.Files))
	expectedDirs := map[string]bool{".": true}
	for _, item := range manifest.Files {
		expected[item.Path] = item
		for dir := filepath.Dir(item.Path); dir != "."; dir = filepath.Dir(dir) {
			expectedDirs[filepath.ToSlash(dir)] = true
		}
	}
	seen := make(map[string]bool, len(expected))
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if entry.IsDir() {
			directory, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			if !expectedDirs[filepath.ToSlash(directory)] {
				return fmt.Errorf("unexpected installed release directory: %s", directory)
			}
			return ownedDirectory(path)
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		name = filepath.ToSlash(name)
		item, ok := expected[name]
		if !ok || !entry.Type().IsRegular() {
			return fmt.Errorf("unexpected installed release entry: %s", name)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		stat, ownerOK := info.Sys().(*syscall.Stat_t)
		if !ownerOK || stat.Uid != uint32(os.Geteuid()) || info.Size() != item.Size || int64(info.Mode().Perm()) != item.Mode {
			return fmt.Errorf("installed release metadata mismatch: %s", name)
		}
		file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if hex.EncodeToString(hash.Sum(nil)) != item.SHA256 {
			return fmt.Errorf("installed release hash mismatch: %s", name)
		}
		seen[name] = true
		return nil
	})
	if err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return errors.New("installed release is incomplete")
	}
	return nil
}

func currentRelease(path, arch string) (string, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return "", errors.New("current is not a symlink")
	}
	value, err := os.Readlink(path)
	if err != nil {
		return "", err
	}
	parts := strings.Split(value, string(filepath.Separator))
	if len(parts) != 2 || parts[0] != "releases" || !strings.HasSuffix(parts[1], "-linux-"+arch) ||
		!validVersion(strings.TrimSuffix(parts[1], "-linux-"+arch)) {
		return "", errors.New("current points outside an installed release")
	}
	if err := ownedDirectory(filepath.Join(filepath.Dir(path), value)); err != nil {
		return "", fmt.Errorf("current target is invalid: %w", err)
	}
	return value, nil
}

// CheckProductionServicesInactive fails closed when systemd cannot prove all
// production units, including the optional egress worker, are stopped.
// A missing unit reports inactive on systemd.
func CheckProductionServicesInactive() error {
	for _, unit := range []string{"osv-sandboxd.service", "osv-sandbox-launcher.service", "osv-sandbox-egress.service"} {
		output, err := exec.Command("systemctl", "show", "-p", "ActiveState", "--value", unit).CombinedOutput()
		if err != nil || strings.TrimSpace(string(output)) != "inactive" {
			return fmt.Errorf("production service is not proven inactive: %s", unit)
		}
	}
	return nil
}
