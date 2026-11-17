package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/doiito/agent_sandbox/internal/otlp"
)

var ErrBusy = errors.New("sandbox capacity exhausted")
var ErrUnavailable = errors.New("sandbox service unavailable")
var ErrTemplateMismatch = errors.New("selected backend or artifact manifest does not match active template")
var ErrInvalidSelector = errors.New("backend and artifact_manifest_sha256 must be provided together as a lowercase SHA-256 digest")

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
	ScratchMiB      int    `json:"scratch_mib"`
	InputMiB        int    `json:"input_mib,omitempty"`
	VsockPort       uint32 `json:"vsock_port"`
	MkfsPath        string `json:"mkfs_path"`
	MkfsLoaderPath  string `json:"mkfs_loader_path,omitempty"`
	MkfsLibraryPath string `json:"mkfs_library_path,omitempty"`
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
	OTLP                 *otlp.Config            `json:"otlp,omitempty"`
	Preview              *PreviewConfig          `json:"preview,omitempty"`
	TemplateID           string                  `json:"template_id,omitempty"`
	Templates            []TemplateConfig        `json:"templates,omitempty"`
	EgressSocket         string                  `json:"egress_socket,omitempty"`
	SessionMaxLifetimeMS int                     `json:"session_max_lifetime_ms,omitempty"`
	Listen               string                  `json:"listen"`
	ArtifactRoot         string                  `json:"artifact_root"`
	RunRoot              string                  `json:"run_root"`
	Backend              string                  `json:"backend"`
	HypervisorPath       string                  `json:"hypervisor_path"`
	Jailer               *JailerConfig           `json:"jailer,omitempty"`
	LinuxGuest           *LinuxGuestConfig       `json:"linux_guest,omitempty"`
	Kernel               Artifact                `json:"kernel"`
	Image                Artifact                `json:"image"`
	AllowedEntrypoints   []string                `json:"allowed_entrypoints"`
	Defaults             Defaults                `json:"defaults"`
	Limits               Limits                  `json:"limits"`
	VMCapacity           *VMCapacityConfig       `json:"vm_capacity,omitempty"`
	WarmPool             *WarmPoolConfig         `json:"warm_pool,omitempty"`
	Production           bool                    `json:"production,omitempty"`
	LauncherSocket       string                  `json:"launcher_socket,omitempty"`
	ArtifactManifest     *ArtifactManifestConfig `json:"artifact_manifest,omitempty"`
	AuthPolicyPath       string                  `json:"auth_policy_path,omitempty"`
	TLS                  *TLSConfig              `json:"tls,omitempty"`
	AuditLogPath         string                  `json:"audit_log_path,omitempty"`
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
		if c.Backend == "firecracker" || c.Backend == "firecracker-linux" || c.Backend == "firecracker-osv" {
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
		} else if c.Backend != "firecracker-osv" {
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
	c.applyCapacityDefaults()
	c.applyWarmPoolDefaults()
}

func (c Config) Validate() error {
	if err := validateAPITelemetry(c.OTLP); err != nil {
		return err
	}
	if c.Preview != nil {
		if !c.Production {
			return errors.New("preview requires production mode with signed templates and tenant policy")
		}
		if err := c.Preview.validate(); err != nil {
			return err
		}
		if c.Preview.Listen == c.Listen {
			return errors.New("preview must use a separate listener")
		}
	}
	if c.EgressSocket != "" && (!filepath.IsAbs(c.EgressSocket) || filepath.Clean(c.EgressSocket) != c.EgressSocket || len(c.EgressSocket) > 100) {
		return errors.New("egress_socket must be a canonical absolute Unix socket path of at most 100 bytes")
	}
	if c.SessionMaxLifetimeMS != 0 && (c.SessionMaxLifetimeMS < sessionMinTTLMS || c.SessionMaxLifetimeMS > sessionMaxLifetimeMS) {
		return errors.New("session_max_lifetime_ms must be 0 or in [1000,600000]")
	}
	if c.ArtifactRoot == "" {
		return errors.New("artifact_root is required")
	}
	if c.Backend != "qemu" && c.Backend != "firecracker" && c.Backend != "firecracker-linux" && c.Backend != "firecracker-osv" {
		return fmt.Errorf("unsupported backend %q", c.Backend)
	}
	if c.Jailer != nil {
		if c.Backend != "firecracker" && c.Backend != "firecracker-linux" && c.Backend != "firecracker-osv" {
			return errors.New("jailer is only valid with a Firecracker backend")
		}
		if c.Jailer.UID < 1 || c.Jailer.GID < 1 {
			return errors.New("jailer uid and gid must be non-root numeric IDs")
		}
		if c.Jailer.CgroupVersion != 2 {
			return errors.New("only jailer cgroup_version=2 is supported")
		}
		if c.Jailer.MemoryOverheadMiB < 1 || c.Jailer.MemoryOverheadMiB > 1<<20 || c.Jailer.NoFileLimit < 32 {
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
			c.Jailer.CPUQuotaPerVCPUUS < 1_000 || c.Jailer.PidsMax < 8 || c.Jailer.PidsMax > 1<<20 || c.Jailer.FileSizeLimitMiB < 1 {
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
		if (c.LinuxGuest.MkfsLoaderPath == "") != (c.LinuxGuest.MkfsLibraryPath == "") {
			return errors.New("mkfs loader and library path must be configured together")
		}
		if c.Production && (!filepath.IsAbs(c.LinuxGuest.MkfsPath) ||
			(c.LinuxGuest.MkfsLoaderPath != "" && (!filepath.IsAbs(c.LinuxGuest.MkfsLoaderPath) || !filepath.IsAbs(c.LinuxGuest.MkfsLibraryPath)))) {
			return errors.New("production mkfs paths must be absolute")
		}
		if c.Limits.MaxOutputByte < 16*1024 {
			return errors.New("firecracker-linux requires max_output_bytes of at least 16384")
		}
	} else if c.LinuxGuest != nil {
		return errors.New("linux_guest is only valid with backend=firecracker-linux")
	}
	if c.Backend == "firecracker-osv" {
		if c.Jailer == nil {
			return errors.New("firecracker-osv requires jailer")
		}
		if c.Image.Format != "" && c.Image.Format != "raw" {
			return errors.New("firecracker-osv requires a raw image")
		}
		if c.Limits.MaxOutputByte < 16*1024 {
			return errors.New("firecracker-osv requires max_output_bytes of at least 16384")
		}
	}
	if c.Production {
		if c.Backend != "firecracker-linux" && c.Backend != "firecracker-osv" {
			return errors.New("production mode requires a signed Linux or OSv Firecracker backend")
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
		if c.Backend != "firecracker-osv" {
			return errors.New("non-production artifact_manifest requires backend=firecracker-osv")
		}
		if c.ArtifactManifest.Path == "" || c.ArtifactManifest.SignaturePath == "" ||
			c.ArtifactManifest.PublicKeyPath == "" || c.ArtifactManifest.SBOMPath == "" {
			return errors.New("OSv diagnostic artifact_manifest requires manifest, signature, public key, and SBOM paths")
		}
	}
	if c.Limits.MaxConcurrent < 1 || c.Limits.MaxConcurrent > 1024 {
		return errors.New("max_concurrent must be in [1,1024]")
	}
	if c.Limits.MinMemoryMiB < 16 || c.Limits.MaxMemoryMiB < c.Limits.MinMemoryMiB || c.Limits.MaxMemoryMiB > 1<<20 {
		return errors.New("invalid memory limits")
	}
	if c.Limits.MaxVCPUs < 1 || c.Limits.MaxVCPUs > 1024 || c.Limits.MaxTimeoutMS < 1 || c.Limits.MaxOutputByte < 1024 {
		return errors.New("invalid cpu, timeout, or output limit")
	}
	if err := c.validateCapacity(); err != nil {
		return err
	}
	if err := c.validateWarmPool(); err != nil {
		return err
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
		if c.Backend == "firecracker-osv" && !validOSvModulePath(entry) {
			return fmt.Errorf("invalid OSv module path %q", entry)
		}
	}
	return c.validateTemplates()
}

type RunRequest struct {
	Entrypoint             string            `json:"entrypoint"`
	Backend                string            `json:"backend,omitempty"`
	ArtifactManifestSHA256 string            `json:"artifact_manifest_sha256,omitempty"`
	Args                   []string          `json:"args,omitempty"`
	Environment            map[string]string `json:"environment,omitempty"`
	Cwd                    string            `json:"cwd,omitempty"`
	Stdin                  []byte            `json:"stdin"`
	MemoryMiB              int               `json:"memory_mib,omitempty"`
	VCPUs                  int               `json:"vcpus,omitempty"`
	TimeoutMS              int               `json:"timeout_ms,omitempty"`
	Network                string            `json:"network,omitempty"`
	InputFiles             []InputFile       `json:"input_files,omitempty"`
	jobID                  string
	jailUID                int
	jailGID                int
	tenantID               string
	poolKey                string
	startupStarted         time.Time
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
	if err := r.ValidateArguments(c); err != nil {
		return err
	}
	if r.Network == "proxy" && c.EgressSocket == "" {
		return errors.New("guest proxy egress service is not configured")
	}
	return nil
}

// ValidateArguments checks request shape and published limits. Gateways such
// as MCP have authenticated capabilities, not the launcher's private paths.
// Deployment validation and signed/tenant policy remain mandatory at the API
// and manager boundaries through Validate and their authorization checks.
func (r RunRequest) ValidateArguments(c Config) error {
	allowed := false
	for _, entry := range c.AllowedEntrypoints {
		allowed = allowed || r.Entrypoint == entry
	}
	if !allowed {
		return fmt.Errorf("entrypoint %q is not allowed", r.Entrypoint)
	}
	if r.Network != "none" && (r.Network != "proxy" || c.Backend != "firecracker-linux" && c.Backend != "firecracker-osv") {
		return errors.New("network must be none, or proxy on a supported signed backend")
	}
	switch c.Backend {
	case "firecracker-linux":
		if err := validateSessionEnvironment(r.Environment, r.Cwd); err != nil {
			return err
		}
		if len(r.Stdin) > linuxJobStdinMaxBytes {
			return errors.New("Linux job stdin exceeds 16 KiB")
		}
	case "firecracker-osv":
		if _, err := validateOSvEnvironment(r.Environment); err != nil {
			return err
		}
		if len(r.Stdin) > osvJobStdinMaxBytes {
			return errors.New("OSv stdin exceeds 16 KiB")
		}
		if r.Cwd != "" {
			return errors.New("cwd requires backend=firecracker-linux")
		}
	default:
		if len(r.Environment) != 0 || r.Cwd != "" || r.Stdin != nil {
			return errors.New("execution inputs are unsupported by this backend")
		}
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
	if err := validateInputFiles(r.InputFiles); err != nil {
		return err
	}
	if c.Backend != "firecracker-linux" && c.Backend != "firecracker-osv" && len(r.InputFiles) != 0 {
		return errors.New("input files require a supported Linux or OSv template")
	}
	argumentLimit := 256
	if c.Backend == "firecracker-linux" || c.Backend == "firecracker-osv" {
		argumentLimit = 4096
	}
	totalArgumentBytes := 0
	for _, arg := range r.Args {
		if len(arg) > argumentLimit {
			return fmt.Errorf("each argument is limited to %d bytes", argumentLimit)
		}
		totalArgumentBytes += len(arg)
		for _, ch := range arg {
			if unicode.IsControl(ch) || (c.Backend != "firecracker-linux" && c.Backend != "firecracker-osv" && ch == '$') {
				return errors.New("arguments contain a character forbidden by this backend")
			}
		}
	}
	if c.Backend == "firecracker-linux" || c.Backend == "firecracker-osv" {
		if c.Backend == "firecracker-osv" {
			// The OSv module path becomes argv[0] inside the guest.
			totalArgumentBytes += len(r.Entrypoint)
		}
		if totalArgumentBytes > 32*1024 {
			return errors.New("guest arguments exceed 32 KiB")
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
	TemplateID             string          `json:"template_id,omitempty"`
	ArtifactManifestSHA256 string          `json:"artifact_manifest_sha256,omitempty"`
	ID                     string          `json:"id"`
	State                  string          `json:"state"`
	Backend                string          `json:"backend"`
	ExitCode               int             `json:"exit_code"`
	TimedOut               bool            `json:"timed_out"`
	Duration               time.Duration   `json:"-"`
	DurationMS             int64           `json:"duration_ms"`
	Output                 string          `json:"output"`
	OutputTruncated        bool            `json:"output_truncated"`
	ProtocolOK             bool            `json:"protocol_ok"`
	GuestResult            json.RawMessage `json:"guest_result,omitempty"`
	StartupMode            string          `json:"startup_mode,omitempty"`
	StartupDurationUS      int64           `json:"startup_duration_us,omitempty"`
	StartupTiming          *StartupTiming  `json:"startup_timing,omitempty"`
	VMBootDurationUS       int64           `json:"vm_boot_duration_us,omitempty"`
}

type DoctorReport struct {
	Ready       bool                `json:"ready"`
	Checks      []DoctorCheck       `json:"checks"`
	VMCapacity  *VMCapacitySnapshot `json:"vm_capacity,omitempty"`
	VMInstances *VMInstanceSnapshot `json:"vm_instances,omitempty"`
	WarmPool    *WarmPoolSnapshot   `json:"warm_pool,omitempty"`
}

type DoctorCheck struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Detail  string `json:"detail"`
	Warning bool   `json:"warning,omitempty"`
}
