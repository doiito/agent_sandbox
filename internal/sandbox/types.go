package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

var ErrBusy = errors.New("sandbox capacity exhausted")

type Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Format string `json:"format,omitempty"`
}

type Limits struct {
	MaxConcurrent int `json:"max_concurrent"`
	MinMemoryMiB  int `json:"min_memory_mib"`
	MaxMemoryMiB  int `json:"max_memory_mib"`
	MaxVCPUs      int `json:"max_vcpus"`
	MaxTimeoutMS  int `json:"max_timeout_ms"`
	MaxOutputByte int `json:"max_output_bytes"`
}

type Defaults struct {
	MemoryMiB int `json:"memory_mib"`
	VCPUs     int `json:"vcpus"`
	TimeoutMS int `json:"timeout_ms"`
}

// JailerConfig enables Firecracker's privileged setup helper. The jail root is
// created below the per-job work directory so the manager can remove the whole
// sandbox after the VMM has exited.
type JailerConfig struct {
	Path              string `json:"path"`
	UID               int    `json:"uid"`
	GID               int    `json:"gid"`
	IdentityPoolSize  int    `json:"identity_pool_size,omitempty"`
	CgroupVersion     int    `json:"cgroup_version"`
	ParentCgroup      string `json:"parent_cgroup,omitempty"`
	CPUPeriodUS       int    `json:"cpu_period_us,omitempty"`
	CPUQuotaPerVCPUUS int    `json:"cpu_quota_per_vcpu_us,omitempty"`
	PidsMax           int    `json:"pids_max,omitempty"`
	IOReadBPS         int64  `json:"io_read_bps,omitempty"`
	IOWriteBPS        int64  `json:"io_write_bps,omitempty"`
	MemoryOverheadMiB int    `json:"memory_overhead_mib"`
	NoFileLimit       int    `json:"no_file_limit"`
	FileSizeLimitMiB  int    `json:"file_size_limit_mib,omitempty"`
}

type LinuxGuestConfig struct {
	ScratchMiB int    `json:"scratch_mib"`
	InputMiB   int    `json:"input_mib,omitempty"`
	VsockPort  uint32 `json:"vsock_port"`
	MkfsPath   string `json:"mkfs_path"`
}

type ArtifactManifestConfig struct {
	Path          string `json:"path"`
	SignaturePath string `json:"signature_path"`
	PublicKeyPath string `json:"public_key_path"`
	SBOMPath      string `json:"sbom_path"`
}

type TLSConfig struct {
	CertFile     string `json:"cert_file"`
	KeyFile      string `json:"key_file"`
	ClientCAFile string `json:"client_ca_file"`
}

type Config struct {
	Listen             string                  `json:"listen"`
	ArtifactRoot       string                  `json:"artifact_root"`
	RunRoot            string                  `json:"run_root"`
	Backend            string                  `json:"backend"`
	HypervisorPath     string                  `json:"hypervisor_path"`
	Jailer             *JailerConfig           `json:"jailer,omitempty"`
	LinuxGuest         *LinuxGuestConfig       `json:"linux_guest,omitempty"`
	Kernel             Artifact                `json:"kernel"`
	Image              Artifact                `json:"image"`
	AllowedEntrypoints []string                `json:"allowed_entrypoints"`
	Defaults           Defaults                `json:"defaults"`
	Limits             Limits                  `json:"limits"`
	Production         bool                    `json:"production,omitempty"`
	LauncherSocket     string                  `json:"launcher_socket,omitempty"`
	ArtifactManifest   *ArtifactManifestConfig `json:"artifact_manifest,omitempty"`
	AuthPolicyPath     string                  `json:"auth_policy_path,omitempty"`
	TLS                *TLSConfig              `json:"tls,omitempty"`
	AuditLogPath       string                  `json:"audit_log_path,omitempty"`
}

func (c *Config) ApplyDefaults() {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8080"
	}
	if c.RunRoot == "" {
		c.RunRoot = "/tmp/osv-sandbox"
	}
	if c.Backend == "" {
		c.Backend = "qemu"
	}
	if c.HypervisorPath == "" {
		if c.Backend == "firecracker" || c.Backend == "firecracker-linux" {
			c.HypervisorPath = "firecracker"
		} else {
			c.HypervisorPath = "qemu-system-x86_64"
		}
	}
	if c.Backend == "firecracker-linux" {
		if c.LinuxGuest == nil {
			c.LinuxGuest = &LinuxGuestConfig{}
		}
		if c.LinuxGuest.ScratchMiB == 0 {
			c.LinuxGuest.ScratchMiB = 256
		}
		if c.LinuxGuest.InputMiB == 0 {
			c.LinuxGuest.InputMiB = 32
		}
		if c.LinuxGuest.VsockPort == 0 {
			c.LinuxGuest.VsockPort = 5000
		}
		if c.LinuxGuest.MkfsPath == "" {
			c.LinuxGuest.MkfsPath = "mkfs.ext4"
		}
	}
	if c.Jailer != nil {
		if c.Jailer.Path == "" {
			c.Jailer.Path = "jailer"
		}
		if c.Jailer.UID == 0 {
			c.Jailer.UID = 65534
		}
		if c.Jailer.GID == 0 {
			c.Jailer.GID = 65534
		}
		if c.Jailer.CgroupVersion == 0 {
			c.Jailer.CgroupVersion = 2
		}
		if c.Jailer.MemoryOverheadMiB == 0 {
			c.Jailer.MemoryOverheadMiB = 128
		}
		if c.Jailer.NoFileLimit == 0 {
			c.Jailer.NoFileLimit = 128
		}
		if c.Jailer.ParentCgroup == "" {
			c.Jailer.ParentCgroup = "osv-sandbox"
		}
		if c.Jailer.CPUPeriodUS == 0 {
			c.Jailer.CPUPeriodUS = 100_000
		}
		if c.Jailer.CPUQuotaPerVCPUUS == 0 {
			c.Jailer.CPUQuotaPerVCPUUS = 100_000
		}
		if c.Jailer.PidsMax == 0 {
			c.Jailer.PidsMax = 64
		}
		if c.Jailer.FileSizeLimitMiB == 0 {
			c.Jailer.FileSizeLimitMiB = 1024
		}
	}
	if len(c.AllowedEntrypoints) == 0 {
		if c.Backend == "firecracker-linux" {
			c.AllowedEntrypoints = []string{"/bin/sh"}
		} else {
			c.AllowedEntrypoints = []string{"/agent"}
		}
	}
	if c.Limits.MaxConcurrent == 0 {
		c.Limits.MaxConcurrent = 4
	}
	if c.Limits.MinMemoryMiB == 0 {
		c.Limits.MinMemoryMiB = 32
	}
	if c.Limits.MaxMemoryMiB == 0 {
		c.Limits.MaxMemoryMiB = 2048
	}
	if c.Limits.MaxVCPUs == 0 {
		c.Limits.MaxVCPUs = 4
	}
	if c.Limits.MaxTimeoutMS == 0 {
		c.Limits.MaxTimeoutMS = 300_000
	}
	if c.Limits.MaxOutputByte == 0 {
		c.Limits.MaxOutputByte = 1 << 20
	}
	if c.Defaults.MemoryMiB == 0 {
		c.Defaults.MemoryMiB = 128
	}
	if c.Defaults.VCPUs == 0 {
		c.Defaults.VCPUs = 1
	}
	if c.Defaults.TimeoutMS == 0 {
		c.Defaults.TimeoutMS = 30_000
	}
}

func (c Config) Validate() error {
	if c.ArtifactRoot == "" {
		return errors.New("artifact_root is required")
	}
	if c.Backend != "qemu" && c.Backend != "firecracker" && c.Backend != "firecracker-linux" {
		return fmt.Errorf("backend must be qemu, firecracker, or firecracker-linux, got %q", c.Backend)
	}
	if c.Jailer != nil {
		if c.Backend != "firecracker" && c.Backend != "firecracker-linux" {
			return errors.New("jailer is only valid with a Firecracker backend")
		}
		if c.Jailer.UID < 1 || c.Jailer.GID < 1 {
			return errors.New("jailer uid and gid must be non-root numeric IDs")
		}
		if c.Jailer.CgroupVersion != 2 {
			return errors.New("only jailer cgroup_version=2 is supported")
		}
		if c.Jailer.MemoryOverheadMiB < 1 || c.Jailer.NoFileLimit < 32 {
			return errors.New("invalid jailer memory overhead or no-file limit")
		}
		if c.Jailer.IdentityPoolSize < 0 || c.Jailer.IdentityPoolSize > 65536 ||
			c.Jailer.UID+c.Jailer.IdentityPoolSize > 1<<31-1 || c.Jailer.GID+c.Jailer.IdentityPoolSize > 1<<31-1 {
			return errors.New("invalid jailer identity pool")
		}
		if c.Jailer.IdentityPoolSize > 0 && c.Jailer.IdentityPoolSize < c.Limits.MaxConcurrent {
			return errors.New("jailer identity_pool_size must cover max_concurrent")
		}
		if !safeCgroupName(c.Jailer.ParentCgroup) {
			return errors.New("invalid jailer parent_cgroup")
		}
		if c.Jailer.CPUPeriodUS < 1_000 || c.Jailer.CPUPeriodUS > 1_000_000 ||
			c.Jailer.CPUQuotaPerVCPUUS < 1_000 || c.Jailer.PidsMax < 8 || c.Jailer.FileSizeLimitMiB < 1 {
			return errors.New("invalid jailer cpu, pids, or file-size limit")
		}
		if c.Jailer.IOReadBPS < 0 || c.Jailer.IOWriteBPS < 0 {
			return errors.New("jailer I/O limits cannot be negative")
		}
	}
	if c.Backend == "firecracker-linux" {
		if c.Jailer == nil {
			return errors.New("firecracker-linux requires jailer")
		}
		if c.LinuxGuest == nil {
			return errors.New("firecracker-linux requires linux_guest")
		}
		if c.LinuxGuest.ScratchMiB < 32 || c.LinuxGuest.ScratchMiB > 16*1024 {
			return errors.New("linux_guest scratch_mib must be in [32,16384]")
		}
		if c.LinuxGuest.InputMiB < 16 || c.LinuxGuest.InputMiB > 1024 {
			return errors.New("linux_guest input_mib must be in [16,1024]")
		}
		if c.LinuxGuest.VsockPort < 1024 {
			return errors.New("linux_guest vsock_port must be at least 1024")
		}
		if c.Limits.MaxOutputByte < 16*1024 {
			return errors.New("firecracker-linux requires max_output_bytes of at least 16384")
		}
	} else if c.LinuxGuest != nil {
		return errors.New("linux_guest is only valid with backend=firecracker-linux")
	}
	if c.Production {
		if c.Backend != "firecracker-linux" {
			return errors.New("production mode currently requires backend=firecracker-linux")
		}
		if c.LauncherSocket == "" || !strings.HasPrefix(c.LauncherSocket, "/") {
			return errors.New("production mode requires an absolute launcher_socket")
		}
		if c.Jailer == nil || c.Jailer.IdentityPoolSize < c.Limits.MaxConcurrent {
			return errors.New("production mode requires a per-concurrency jailer identity pool")
		}
		if c.ArtifactManifest == nil || c.ArtifactManifest.Path == "" ||
			c.ArtifactManifest.SignaturePath == "" || c.ArtifactManifest.PublicKeyPath == "" || c.ArtifactManifest.SBOMPath == "" {
			return errors.New("production mode requires a signed artifact_manifest")
		}
		if c.AuthPolicyPath == "" || !strings.HasPrefix(c.AuthPolicyPath, "/") {
			return errors.New("production mode requires an absolute auth_policy_path")
		}
		if c.TLS == nil || !filepath.IsAbs(c.TLS.CertFile) || !filepath.IsAbs(c.TLS.KeyFile) || !filepath.IsAbs(c.TLS.ClientCAFile) {
			return errors.New("production mode requires absolute mTLS certificate, key, and client CA paths")
		}
		if !filepath.IsAbs(c.AuditLogPath) {
			return errors.New("production mode requires an absolute audit_log_path")
		}
	} else if c.ArtifactManifest != nil {
		return errors.New("artifact_manifest is only accepted with production=true")
	}
	if c.Limits.MaxConcurrent < 1 || c.Limits.MaxConcurrent > 1024 {
		return errors.New("max_concurrent must be in [1,1024]")
	}
	if c.Limits.MinMemoryMiB < 16 || c.Limits.MaxMemoryMiB < c.Limits.MinMemoryMiB {
		return errors.New("invalid memory limits")
	}
	if c.Limits.MaxVCPUs < 1 || c.Limits.MaxTimeoutMS < 1 || c.Limits.MaxOutputByte < 1024 {
		return errors.New("invalid cpu, timeout, or output limit")
	}
	if c.Production && c.Limits.MaxOutputByte > 1<<20 {
		return errors.New("production max_output_bytes must not exceed 1 MiB")
	}
	if c.Defaults.MemoryMiB < c.Limits.MinMemoryMiB || c.Defaults.MemoryMiB > c.Limits.MaxMemoryMiB ||
		c.Defaults.VCPUs < 1 || c.Defaults.VCPUs > c.Limits.MaxVCPUs ||
		c.Defaults.TimeoutMS < 1 || c.Defaults.TimeoutMS > c.Limits.MaxTimeoutMS {
		return errors.New("defaults exceed configured limits")
	}
	if len(c.AllowedEntrypoints) == 0 {
		return errors.New("at least one allowed_entrypoint is required")
	}
	for _, entry := range c.AllowedEntrypoints {
		if !strings.HasPrefix(entry, "/") || strings.ContainsAny(entry, " \t\r\n;!&$") {
			return fmt.Errorf("unsafe allowed entrypoint %q", entry)
		}
	}
	return nil
}

type RunRequest struct {
	Entrypoint string      `json:"entrypoint"`
	Args       []string    `json:"args,omitempty"`
	MemoryMiB  int         `json:"memory_mib,omitempty"`
	VCPUs      int         `json:"vcpus,omitempty"`
	TimeoutMS  int         `json:"timeout_ms,omitempty"`
	Network    string      `json:"network,omitempty"`
	InputFiles []InputFile `json:"input_files,omitempty"`
	jobID      string
	jailUID    int
	jailGID    int
	tenantID   string
}

type InputFile struct {
	Path string `json:"path"`
	Data []byte `json:"data"`
	Mode uint32 `json:"mode,omitempty"`
}

func safeCgroupName(value string) bool {
	if value == "" || strings.HasPrefix(value, "/") || strings.Contains(value, "..") {
		return false
	}
	for _, ch := range value {
		if !(ch == '-' || ch == '_' || ch == '/' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9') {
			return false
		}
	}
	return true
}

func (r *RunRequest) Normalize(c Config) {
	if r.Entrypoint == "" {
		r.Entrypoint = c.AllowedEntrypoints[0]
	}
	if r.MemoryMiB == 0 {
		r.MemoryMiB = c.Defaults.MemoryMiB
	}
	if r.VCPUs == 0 {
		r.VCPUs = c.Defaults.VCPUs
	}
	if r.TimeoutMS == 0 {
		r.TimeoutMS = c.Defaults.TimeoutMS
	}
	if r.Network == "" {
		r.Network = "none"
	}
}

func (r RunRequest) Validate(c Config) error {
	allowed := false
	for _, entry := range c.AllowedEntrypoints {
		allowed = allowed || r.Entrypoint == entry
	}
	if !allowed {
		return fmt.Errorf("entrypoint %q is not allowed", r.Entrypoint)
	}
	if r.Network != "none" {
		return errors.New("only network=none is implemented; use a policy egress proxy before enabling networking")
	}
	if r.MemoryMiB < c.Limits.MinMemoryMiB || r.MemoryMiB > c.Limits.MaxMemoryMiB {
		return fmt.Errorf("memory_mib must be in [%d,%d]", c.Limits.MinMemoryMiB, c.Limits.MaxMemoryMiB)
	}
	if r.VCPUs < 1 || r.VCPUs > c.Limits.MaxVCPUs {
		return fmt.Errorf("vcpus must be in [1,%d]", c.Limits.MaxVCPUs)
	}
	if r.TimeoutMS < 1 || r.TimeoutMS > c.Limits.MaxTimeoutMS {
		return fmt.Errorf("timeout_ms must be in [1,%d]", c.Limits.MaxTimeoutMS)
	}
	if len(r.Args) > 64 {
		return errors.New("at most 64 arguments are allowed")
	}
	if len(r.InputFiles) > 64 {
		return errors.New("at most 64 input files are allowed")
	}
	inputBytes := 0
	seenInputPaths := make(map[string]struct{}, len(r.InputFiles))
	for _, input := range r.InputFiles {
		clean := filepath.Clean(input.Path)
		if input.Path == "" || filepath.IsAbs(input.Path) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean != input.Path {
			return errors.New("input file paths must be clean relative paths")
		}
		if _, exists := seenInputPaths[clean]; exists {
			return errors.New("duplicate input file path")
		}
		seenInputPaths[clean] = struct{}{}
		if input.Mode != 0 && input.Mode != 0o444 {
			return errors.New("input files are data-only and mode must be 0444")
		}
		inputBytes += len(input.Data)
	}
	if inputBytes > 512*1024 {
		return errors.New("input files exceed 512 KiB")
	}
	if c.Backend != "firecracker-linux" && len(r.InputFiles) != 0 {
		return errors.New("input files require backend=firecracker-linux")
	}
	argumentLimit := 256
	if c.Backend == "firecracker-linux" {
		argumentLimit = 4096
	}
	totalArgumentBytes := 0
	for _, arg := range r.Args {
		if len(arg) > argumentLimit {
			return fmt.Errorf("each argument is limited to %d bytes", argumentLimit)
		}
		totalArgumentBytes += len(arg)
		for _, ch := range arg {
			if unicode.IsControl(ch) || c.Backend != "firecracker-linux" && ch == '$' {
				return errors.New("arguments contain a character forbidden by this backend")
			}
		}
	}
	if c.Backend == "firecracker-linux" {
		if totalArgumentBytes > 32*1024 {
			return errors.New("Linux guest arguments exceed 32 KiB")
		}
		return nil
	}
	cmdline, err := OSvCommandLine(r.Entrypoint, r.Args)
	if err != nil {
		return err
	}
	// include room for --nopci and --console=serial; OSv max_cmdline is 1024.
	if len(cmdline) > 900 {
		return errors.New("encoded OSv command line exceeds 900 bytes")
	}
	return nil
}

type RunResult struct {
	ID              string          `json:"id"`
	State           string          `json:"state"`
	Backend         string          `json:"backend"`
	ExitCode        int             `json:"exit_code"`
	TimedOut        bool            `json:"timed_out"`
	Duration        time.Duration   `json:"-"`
	DurationMS      int64           `json:"duration_ms"`
	Output          string          `json:"output"`
	OutputTruncated bool            `json:"output_truncated"`
	ProtocolOK      bool            `json:"protocol_ok"`
	GuestResult     json.RawMessage `json:"guest_result,omitempty"`
}

type DoctorReport struct {
	Ready  bool          `json:"ready"`
	Checks []DoctorCheck `json:"checks"`
}

type DoctorCheck struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Detail  string `json:"detail"`
	Warning bool   `json:"warning,omitempty"`
}
