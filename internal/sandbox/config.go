package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// LoadConfig performs strict decoding so production launcher and unprivileged
// API processes interpret exactly the same policy document.
func LoadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return Config{}, errors.New("configuration must be a regular file")
	}
	decoder := json.NewDecoder(io.LimitReader(f, 1<<20))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode %s: %w", path, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Config{}, fmt.Errorf("decode %s: expected exactly one JSON object", path)
	}
	config.ApplyDefaults()
	if config.Production {
		if err := trustedProductionConfigPath(path); err != nil {
			return Config{}, fmt.Errorf("untrusted production configuration: %w", err)
		}
	}
	return config, config.Validate()
}

func trustedProductionConfigPath(path string) error {
	return trustedCanonicalRootOwnedPath(path, false)
}

func trustedManagedRunRootPath(path string) error {
	return trustedCanonicalRootOwnedPath(path, true)
}

func trustedCanonicalRootOwnedPath(path string, directory bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("path must be canonical and absolute")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s contains a symbolic link", current)
		}
		if ((current != path || directory) && !info.IsDir()) ||
			(current == path && !directory && !info.Mode().IsRegular()) {
			return fmt.Errorf("%s has the wrong file type", current)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s must be root owned and not writable by group or other", current)
		}
		if current == string(filepath.Separator) {
			break
		}
	}
	return nil
}
