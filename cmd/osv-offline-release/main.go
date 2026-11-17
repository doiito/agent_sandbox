package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/doiito/agent_sandbox/internal/offlinebundle"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: osv-offline-release keygen|pack|verify|install|switch [flags]")
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	source := f.String("source", "", "release payload directory")
	archive := f.String("archive", "", "release tar path")
	privatePath := f.String("private-key", "", "out-of-band Ed25519 PEM signing key")
	publicPath := f.String("public-key", "", "out-of-band Ed25519 PEM trust anchor")
	version := f.String("version", "", "immutable release version")
	arch := f.String("arch", runtime.GOARCH, "target Go architecture: amd64 or arm64")
	commit := f.String("commit", "", "source revision")
	validUntil := f.String("valid-until", "", "release signature expiry in RFC3339 UTC")
	root := f.String("root", "", "installation root")
	runRoot := f.String("run-root", "/var/lib/osv-sandbox/run", "launcher run_root for a release switch")
	cgroupRoot := f.String("cgroup-root", "/sys/fs/cgroup/osv-sandbox", "jailer cgroup root for a release switch")
	allowTestCandidate := f.Bool("allow-test-candidate", false, "allow a dirty test candidate for isolated validation only")
	jsonOutput := f.Bool("json", false, "verify: return authenticated manifest and whole archive SHA256 as JSON")
	referencePath := f.String("reference-manifest", "", "pack: authenticated reference manifest supplied by release preflight")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *jsonOutput && args[0] != "verify" {
		return errors.New("-json is available only for verify")
	}
	if *referencePath != "" && args[0] != "pack" {
		return errors.New("-reference-manifest is available only for pack")
	}
	switch args[0] {
	case "keygen":
		if *privatePath == "" || *publicPath == "" {
			return errors.New("keygen requires -private-key and -public-key")
		}
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		privateDER, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			return err
		}
		publicDER, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			return err
		}
		if err := os.WriteFile(*privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
			return err
		}
		return os.WriteFile(*publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644)
	case "pack":
		if *source == "" || *archive == "" || *privatePath == "" {
			return errors.New("pack requires -source, -archive and -private-key")
		}
		key, err := readPrivate(*privatePath)
		if err != nil {
			return err
		}
		expires, err := time.Parse(time.RFC3339, *validUntil)
		if err != nil {
			return fmt.Errorf("pack requires -valid-until RFC3339: %w", err)
		}
		out, err := os.OpenFile(*archive, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		if *referencePath == "" {
			err = offlinebundle.Pack(*source, out, *version, *arch, *commit, expires, key)
		} else {
			var reference offlinebundle.Manifest
			reference, err = readReference(*referencePath)
			if err == nil {
				err = offlinebundle.PackWithReference(*source, out, *version, *arch, *commit, expires, key, reference)
			}
		}
		if err == nil {
			err = out.Sync()
		}
		if closeErr := out.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(*archive)
			return err
		}
		return nil
	case "verify", "install":
		if *archive == "" || *publicPath == "" {
			return errors.New("verify/install requires -archive and -public-key")
		}
		key, err := readPublic(*publicPath)
		if err != nil {
			return err
		}
		if args[0] == "install" {
			if *root == "" {
				return errors.New("install requires -root")
			}
			installed, err := offlinebundle.Install(*archive, key, *root)
			if err == nil {
				fmt.Println(installed)
			}
			return err
		}
		file, err := os.Open(*archive)
		if err != nil {
			return err
		}
		before, statErr := file.Stat()
		if statErr != nil {
			file.Close()
			return statErr
		}
		digest := sha256.New()
		manifest, verifyErr := offlinebundle.Verify(io.TeeReader(file, digest), key, *arch, "")
		after, afterErr := file.Stat()
		readBytes, seekErr := file.Seek(0, io.SeekCurrent)
		closeErr := file.Close()
		if verifyErr != nil {
			return verifyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if afterErr != nil || seekErr != nil || before.Size() != readBytes || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
			return errors.New("release archive changed while verifying")
		}
		if *jsonOutput {
			return json.NewEncoder(os.Stdout).Encode(struct {
				Manifest      offlinebundle.Manifest `json:"manifest"`
				ArchiveSHA256 string                 `json:"archive_sha256"`
				ArchiveBytes  int64                  `json:"archive_bytes"`
			}{manifest, hex.EncodeToString(digest.Sum(nil)), readBytes})
		}
		fmt.Printf("verified version=%s arch=%s files=%d commit=%s\n", manifest.Version, manifest.Arch, len(manifest.Files), manifest.Commit)
		return nil
	case "switch":
		if *archive == "" || *publicPath == "" || *root == "" {
			return errors.New("switch requires -archive, -public-key and -root")
		}
		if os.Geteuid() != 0 {
			return errors.New("switch requires root")
		}
		key, err := readPublic(*publicPath)
		if err != nil {
			return err
		}
		result, err := offlinebundle.Switch(offlinebundle.SwitchOptions{
			Archive: *archive, PublicKey: key, Root: *root, RunRoot: *runRoot,
			CgroupRoot: *cgroupRoot, AllowTestCandidate: *allowTestCandidate,
			CheckServices: offlinebundle.CheckProductionServicesInactive,
		})
		if err != nil {
			return err
		}
		fmt.Printf("active=%s previous=%s changed=%t\n", result.Active, result.Previous, result.Changed)
		return nil
	default:
		return errors.New("unknown command: " + args[0])
	}
}

func readReference(path string) (offlinebundle.Manifest, error) {
	var reference offlinebundle.Manifest
	info, err := os.Lstat(path)
	if err != nil {
		return reference, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return reference, errors.New("reference manifest must be a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return reference, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	closeErr := file.Close()
	if readErr != nil {
		return reference, readErr
	}
	if closeErr != nil {
		return reference, closeErr
	}
	if len(data) > 1<<20 {
		return reference, errors.New("reference manifest exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&reference); err != nil {
		return reference, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return reference, errors.New("unexpected trailing reference JSON")
	}
	return reference, nil
}

func readPrivate(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || len(rest) != 0 {
		return nil, errors.New("invalid private PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key must be Ed25519")
	}
	return key, nil
}

func readPublic(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || len(rest) != 0 {
		return nil, errors.New("invalid public PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key must be Ed25519")
	}
	return key, nil
}
