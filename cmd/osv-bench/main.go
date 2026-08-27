package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

type options struct {
	backend         string
	iterations      int
	warmup          int
	concurrency     int
	timeout         time.Duration
	memoryMiB       int
	vcpus           int
	operation       string
	operationArgs   string
	evictArtifacts  bool
	includeOutput   bool
	kernel          string
	qemuImage       string
	rawImage        string
	qemuPath        string
	firecrackerPath string
	output          string
}

type sample struct {
	Index            int    `json:"index"`
	Success          bool   `json:"success"`
	ResultLatencyUS  int64  `json:"result_latency_us"`
	ProcessLatencyUS int64  `json:"process_latency_us"`
	PeakRSSKiB       int64  `json:"peak_rss_kib"`
	PeakThreads      int    `json:"peak_threads"`
	PeakFDs          int    `json:"peak_fds"`
	PeakMappings     int    `json:"peak_mappings"`
	SeccompMode      int    `json:"seccomp_mode"`
	CapEff           string `json:"cap_eff,omitempty"`
	UserCPUUS        int64  `json:"user_cpu_us"`
	SystemCPUUS      int64  `json:"system_cpu_us"`
	ExitCode         int    `json:"vmm_exit_code"`
	Error            string `json:"error,omitempty"`
	Output           string `json:"output,omitempty"`
}

type summary struct {
	Backend             string   `json:"backend"`
	Iterations          int      `json:"iterations"`
	Concurrency         int      `json:"concurrency"`
	Successes           int      `json:"successes"`
	Failures            int      `json:"failures"`
	ThroughputJobsSec   float64  `json:"throughput_jobs_sec"`
	ResultP50US         int64    `json:"result_p50_us"`
	ResultP90US         int64    `json:"result_p90_us"`
	ResultP99US         int64    `json:"result_p99_us"`
	ResultMaxUS         int64    `json:"result_max_us"`
	ProcessP50US        int64    `json:"process_p50_us"`
	ProcessP99US        int64    `json:"process_p99_us"`
	PeakRSSP50KiB       int64    `json:"peak_rss_p50_kib"`
	PeakRSSP99KiB       int64    `json:"peak_rss_p99_kib"`
	PeakRSSMaxKiB       int64    `json:"peak_rss_max_kib"`
	PeakThreadsMax      int      `json:"peak_threads_max"`
	PeakFDsMax          int      `json:"peak_fds_max"`
	PeakMappingsMax     int      `json:"peak_mappings_max"`
	ObservedSeccompMode []int    `json:"observed_seccomp_modes"`
	ObservedCapEff      []string `json:"observed_cap_eff"`
	Samples             []sample `json:"samples"`
}

type report struct {
	GeneratedAt string         `json:"generated_at"`
	Host        map[string]any `json:"host"`
	Options     optionsJSON    `json:"options"`
	Results     []summary      `json:"results"`
}

type optionsJSON struct {
	Iterations  int    `json:"iterations"`
	Warmup      int    `json:"warmup"`
	Concurrency int    `json:"concurrency"`
	TimeoutMS   int64  `json:"timeout_ms"`
	MemoryMiB   int    `json:"memory_mib"`
	VCPUs       int    `json:"vcpus"`
	Operation   string `json:"operation"`
	CacheMode   string `json:"cache_mode"`
}

func main() {
	var o options
	flag.StringVar(&o.backend, "backend", "both", "qemu, firecracker, or both")
	flag.IntVar(&o.iterations, "iterations", 100, "measured jobs per backend")
	flag.IntVar(&o.warmup, "warmup", 5, "unmeasured warm-up jobs per backend")
	flag.IntVar(&o.concurrency, "concurrency", 1, "parallel jobs per backend")
	flag.DurationVar(&o.timeout, "timeout", 5*time.Second, "per-job timeout")
	flag.IntVar(&o.memoryMiB, "memory-mib", 128, "guest memory")
	flag.IntVar(&o.vcpus, "vcpus", 1, "guest vCPUs")
	flag.StringVar(&o.operation, "operation", "probe", "guest operation")
	flag.StringVar(&o.operationArgs, "operation-args", "", "comma-separated guest operation arguments")
	flag.BoolVar(&o.evictArtifacts, "evict-artifacts", false, "request per-artifact page-cache eviction before each job")
	flag.BoolVar(&o.includeOutput, "include-output", false, "include successful guest/VMM output in samples")
	flag.StringVar(&o.kernel, "kernel", "/opt/osv-sandbox/artifacts/loader-stripped.elf", "OSv kernel")
	flag.StringVar(&o.qemuImage, "qemu-image", "/opt/osv-sandbox/artifacts/usr.img", "QEMU qcow2 image")
	flag.StringVar(&o.rawImage, "raw-image", "/opt/osv-sandbox/artifacts/osv-agent.raw", "Firecracker raw image")
	flag.StringVar(&o.qemuPath, "qemu", "/usr/bin/qemu-system-x86_64", "QEMU executable")
	flag.StringVar(&o.firecrackerPath, "firecracker", "/usr/local/bin/firecracker", "Firecracker executable")
	flag.StringVar(&o.output, "output", "", "write JSON report to this path")
	flag.Parse()
	if o.iterations < 1 || o.warmup < 0 || o.concurrency < 1 || o.memoryMiB < 32 || o.vcpus < 1 {
		fatalf("invalid numeric option")
	}
	if o.evictArtifacts && o.concurrency != 1 {
		fatalf("-evict-artifacts requires -concurrency=1")
	}
	if o.backend != "qemu" && o.backend != "firecracker" && o.backend != "both" {
		fatalf("invalid backend %q", o.backend)
	}

	backends := []string{o.backend}
	if o.backend == "both" {
		backends = []string{"qemu", "firecracker"}
	}
	r := report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Host:        hostInfo(),
		Options: optionsJSON{
			Iterations: o.iterations, Warmup: o.warmup, Concurrency: o.concurrency,
			TimeoutMS: o.timeout.Milliseconds(), MemoryMiB: o.memoryMiB,
			VCPUs: o.vcpus, Operation: o.operation, CacheMode: cacheMode(o),
		},
	}
	for _, backend := range backends {
		result, err := benchmark(o, backend)
		if err != nil {
			fatalf("%s benchmark: %v", backend, err)
		}
		r.Results = append(r.Results, result)
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		fatalf("encode report: %v", err)
	}
	data = append(data, '\n')
	if o.output != "" {
		if err := os.WriteFile(o.output, data, 0o600); err != nil {
			fatalf("write report: %v", err)
		}
	}
	_, _ = os.Stdout.Write(data)
}

func benchmark(o options, backend string) (summary, error) {
	for i := 0; i < o.warmup; i++ {
		if _, err := runOne(o, backend, -1); err != nil {
			return summary{}, fmt.Errorf("warmup %d: %w", i, err)
		}
	}
	samples := make([]sample, o.iterations)
	jobs := make(chan int)
	var wg sync.WaitGroup
	started := time.Now()
	for worker := 0; worker < o.concurrency; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				got, err := runOne(o, backend, index)
				if err != nil && got.Error == "" {
					got.Error = err.Error()
				}
				samples[index] = got
			}
		}()
	}
	for index := range samples {
		jobs <- index
	}
	close(jobs)
	wg.Wait()
	elapsed := time.Since(started)
	return summarize(backend, o.concurrency, samples, elapsed), nil
}

func runOne(o options, backend string, index int) (sample, error) {
	idBytes := make([]byte, 12)
	if _, err := rand.Read(idBytes); err != nil {
		return sample{Index: index}, err
	}
	jobID := hex.EncodeToString(idBytes)
	workdir, err := os.MkdirTemp("", "osv-bench-")
	if err != nil {
		return sample{Index: index}, err
	}
	if o.evictArtifacts {
		image := o.rawImage
		if backend == "qemu" {
			image = o.qemuImage
		}
		if err := evictFileCache(o.kernel, image); err != nil {
			return sample{Index: index}, err
		}
	}
	defer os.RemoveAll(workdir)

	args := []string{"--sandbox-job-id", jobID, o.operation}
	if o.operationArgs != "" {
		args = append(args, strings.Split(o.operationArgs, ",")...)
	}
	req := sandbox.RunRequest{Entrypoint: "/agent", Args: args, MemoryMiB: o.memoryMiB, VCPUs: o.vcpus}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	var cmd *exec.Cmd
	if backend == "qemu" {
		cmd, err = (sandbox.QEMUBackend{Path: o.qemuPath}).Command(ctx, req, sandbox.ResolvedArtifacts{
			KernelPath: o.kernel, ImagePath: o.qemuImage, Format: "qcow2",
		}, workdir)
	} else {
		cmd, err = (sandbox.FirecrackerBackend{Path: o.firecrackerPath}).Command(ctx, req, sandbox.ResolvedArtifacts{
			KernelPath: o.kernel, ImagePath: o.rawImage, Format: "raw",
		}, workdir)
	}
	if err != nil {
		return sample{Index: index}, err
	}
	cmd.Dir = workdir
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	capture := &resultCapture{jobID: jobID}
	cmd.Stdout, cmd.Stderr = capture, capture
	started := time.Now()
	if err := cmd.Start(); err != nil {
		return sample{Index: index}, err
	}
	metricsDone := make(chan procMetrics, 1)
	go sampleProcess(cmd.Process.Pid, metricsDone)
	waitErr := cmd.Wait()
	finished := time.Now()
	metrics := <-metricsDone
	output, resultAt, protocolOK, guestOK := capture.result()
	exitCode := 0
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	got := sample{
		Index: index, Success: protocolOK && guestOK && !resultAt.IsZero(),
		ProcessLatencyUS: finished.Sub(started).Microseconds(), PeakRSSKiB: metrics.peakRSSKiB,
		PeakThreads: metrics.peakThreads, PeakFDs: metrics.peakFDs, PeakMappings: metrics.peakMappings,
		SeccompMode: metrics.seccompMode, CapEff: metrics.capEff, ExitCode: exitCode,
	}
	if cmd.ProcessState != nil {
		got.UserCPUUS = cmd.ProcessState.UserTime().Microseconds()
		got.SystemCPUUS = cmd.ProcessState.SystemTime().Microseconds()
	}
	if !resultAt.IsZero() {
		got.ResultLatencyUS = resultAt.Sub(started).Microseconds()
	}
	if !got.Success {
		got.Output = output
		if ctx.Err() != nil {
			got.Error = ctx.Err().Error()
		} else if waitErr != nil {
			got.Error = waitErr.Error()
		} else {
			got.Error = "missing or invalid guest result"
		}
		return got, errors.New(got.Error)
	}
	if o.includeOutput {
		got.Output = output
	}
	return got, nil
}

type resultCapture struct {
	mu       sync.Mutex
	jobID    string
	buffer   bytes.Buffer
	resultAt time.Time
}

func (c *resultCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.buffer.Write(p)
	if c.resultAt.IsZero() && bytes.Contains(c.buffer.Bytes(), []byte("OSV_AGENT_RESULT ")) {
		c.resultAt = time.Now()
	}
	return n, err
}

func (c *resultCapture) result() (string, time.Time, bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	output := c.buffer.String()
	protocolOK, guestOK := false, false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSuffix(line, "\r")
		const prefix = "OSV_AGENT_RESULT "
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		var envelope struct {
			Protocol string `json:"protocol"`
			JobID    string `json:"job_id"`
			OK       *bool  `json:"ok"`
		}
		if json.Unmarshal([]byte(strings.TrimPrefix(line, prefix)), &envelope) == nil &&
			envelope.Protocol == "osv-agent/v1" && envelope.JobID == c.jobID && envelope.OK != nil {
			protocolOK, guestOK = true, *envelope.OK
		}
	}
	return output, c.resultAt, protocolOK, guestOK
}

type procMetrics struct {
	peakRSSKiB            int64
	peakThreads           int
	peakFDs, peakMappings int
	seccompMode           int
	capEff                string
}

func sampleProcess(pid int, done chan<- procMetrics) {
	var got procMetrics
	ticker := time.NewTicker(250 * time.Microsecond)
	defer ticker.Stop()
	for {
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			done <- got
			return
		}
		for _, line := range strings.Split(string(status), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			switch strings.TrimSuffix(fields[0], ":") {
			case "VmRSS":
				value, _ := strconv.ParseInt(fields[1], 10, 64)
				if value > got.peakRSSKiB {
					got.peakRSSKiB = value
				}
			case "Threads":
				value, _ := strconv.Atoi(fields[1])
				if value > got.peakThreads {
					got.peakThreads = value
				}
			case "Seccomp":
				value, _ := strconv.Atoi(fields[1])
				if value > got.seccompMode {
					got.seccompMode = value
				}
			case "CapEff":
				got.capEff = fields[1]
			}
		}
		if entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid)); err == nil && len(entries) > got.peakFDs {
			got.peakFDs = len(entries)
		}
		if maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid)); err == nil {
			count := bytes.Count(maps, []byte{'\n'})
			if count > got.peakMappings {
				got.peakMappings = count
			}
		}
		<-ticker.C
	}
}

func summarize(backend string, concurrency int, samples []sample, elapsed time.Duration) summary {
	resultLatency := make([]int64, 0, len(samples))
	processLatency := make([]int64, 0, len(samples))
	rss := make([]int64, 0, len(samples))
	seccomp := map[int]struct{}{}
	caps := map[string]struct{}{}
	s := summary{Backend: backend, Iterations: len(samples), Concurrency: concurrency, Samples: samples}
	for _, sample := range samples {
		if sample.Success {
			s.Successes++
			resultLatency = append(resultLatency, sample.ResultLatencyUS)
			processLatency = append(processLatency, sample.ProcessLatencyUS)
			rss = append(rss, sample.PeakRSSKiB)
		} else {
			s.Failures++
		}
		if sample.PeakThreads > s.PeakThreadsMax {
			s.PeakThreadsMax = sample.PeakThreads
		}
		if sample.PeakFDs > s.PeakFDsMax {
			s.PeakFDsMax = sample.PeakFDs
		}
		if sample.PeakMappings > s.PeakMappingsMax {
			s.PeakMappingsMax = sample.PeakMappings
		}
		seccomp[sample.SeccompMode] = struct{}{}
		if sample.CapEff != "" {
			caps[sample.CapEff] = struct{}{}
		}
	}
	if elapsed > 0 {
		s.ThroughputJobsSec = float64(s.Successes) / elapsed.Seconds()
	}
	s.ResultP50US, s.ResultP90US, s.ResultP99US, s.ResultMaxUS = percentile(resultLatency, 0.50), percentile(resultLatency, 0.90), percentile(resultLatency, 0.99), percentile(resultLatency, 1)
	s.ProcessP50US, s.ProcessP99US = percentile(processLatency, 0.50), percentile(processLatency, 0.99)
	s.PeakRSSP50KiB, s.PeakRSSP99KiB, s.PeakRSSMaxKiB = percentile(rss, 0.50), percentile(rss, 0.99), percentile(rss, 1)
	for value := range seccomp {
		s.ObservedSeccompMode = append(s.ObservedSeccompMode, value)
	}
	sort.Ints(s.ObservedSeccompMode)
	for value := range caps {
		s.ObservedCapEff = append(s.ObservedCapEff, value)
	}
	sort.Strings(s.ObservedCapEff)
	return s
}

func percentile(values []int64, quantile float64) int64 {
	if len(values) == 0 {
		return 0
	}
	copyOf := append([]int64(nil), values...)
	sort.Slice(copyOf, func(i, j int) bool { return copyOf[i] < copyOf[j] })
	index := int(float64(len(copyOf)-1) * quantile)
	return copyOf[index]
}

func cacheMode(o options) string {
	if o.evictArtifacts {
		return "artifact-cache-evicted"
	}
	return "warm"
}

func evictFileCache(paths ...string) error {
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		_, _, errno := syscall.Syscall6(syscall.SYS_FADVISE64, file.Fd(), 0, 0, 4, 0, 0)
		closeErr := file.Close()
		if errno != 0 {
			return fmt.Errorf("fadvise DONTNEED %s: %w", path, errno)
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func hostInfo() map[string]any {
	host := map[string]any{}
	for key, path := range map[string]string{
		"kernel": "/proc/sys/kernel/osrelease", "hostname": "/proc/sys/kernel/hostname",
		"cpu_model": "/proc/cpuinfo", "meminfo": "/proc/meminfo",
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		value := strings.TrimSpace(string(data))
		if key == "cpu_model" {
			for _, line := range strings.Split(value, "\n") {
				if strings.HasPrefix(line, "model name") {
					value = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
					break
				}
			}
		} else if key == "meminfo" {
			value = strings.SplitN(value, "\n", 2)[0]
		}
		host[key] = value
	}
	if qemu, err := exec.Command("/usr/bin/qemu-system-x86_64", "--version").Output(); err == nil {
		host["qemu_version"] = strings.SplitN(strings.TrimSpace(string(qemu)), "\n", 2)[0]
	}
	if fc, err := exec.Command("/usr/local/bin/firecracker", "--version").CombinedOutput(); err == nil {
		for _, line := range strings.Split(string(fc), "\n") {
			if strings.HasPrefix(line, "Firecracker ") {
				host["firecracker_version"] = strings.TrimSpace(line)
				break
			}
		}
	}
	if hash, err := exec.Command("sha256sum", filepath.Clean("/opt/osv-sandbox/artifacts/usr.img")).Output(); err == nil {
		host["qemu_image_sha256"] = strings.Fields(string(hash))[0]
	}
	return host
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "osv-bench: "+format+"\n", args...)
	os.Exit(1)
}
