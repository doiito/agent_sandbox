package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func productionDoctorChecks(config Config) []DoctorCheck {
	checks := []DoctorCheck{{Name: "production-policy", OK: true, Detail: "split launcher, unique jail identities, signed artifacts, mTLS and tenant policy required"}}
	if data, err := os.ReadFile("/proc/swaps"); err != nil {
		checks = append(checks, DoctorCheck{Name: "swap", Detail: err.Error()})
	} else if len(strings.Fields(string(data))) > 5 {
		checks = append(checks, DoctorCheck{Name: "swap", Detail: "host swap is enabled; guest memory can persist outside the microVM lifecycle"})
	} else {
		checks = append(checks, DoctorCheck{Name: "swap", OK: true, Detail: "disabled"})
	}
	controllers, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers")
	required := []string{"cpu", "io", "memory", "pids"}
	missing := make([]string, 0)
	for _, controller := range required {
		if err != nil || !containsWord(string(controllers), controller) {
			missing = append(missing, controller)
		}
	}
	if len(missing) != 0 {
		checks = append(checks, DoctorCheck{Name: "cgroup-controllers", Detail: "missing cgroup v2 controllers: " + strings.Join(missing, ",")})
	} else {
		checks = append(checks, DoctorCheck{Name: "cgroup-controllers", OK: true, Detail: strings.Join(required, ",")})
	}
	if _, err := LoadAuthenticator(config.AuthPolicyPath); err != nil {
		checks = append(checks, DoctorCheck{Name: "tenant-auth", Detail: err.Error()})
	} else {
		checks = append(checks, DoctorCheck{Name: "tenant-auth", OK: true, Detail: "hashed token RBAC, rate and concurrency policy loaded"})
	}
	if _, err := LoadServerTLS(config.TLS); err != nil {
		checks = append(checks, DoctorCheck{Name: "mtls", Detail: err.Error()})
	} else {
		checks = append(checks, DoctorCheck{Name: "mtls", OK: true, Detail: "TLS 1.3 with required client certificates"})
	}
	vulnerabilities, _ := filepath.Glob("/sys/devices/system/cpu/vulnerabilities/*")
	unsafe := make([]string, 0)
	for _, path := range vulnerabilities {
		data, err := os.ReadFile(path)
		value := strings.TrimSpace(string(data))
		if err != nil || strings.HasPrefix(value, "Vulnerable") || strings.HasPrefix(value, "Unknown") {
			unsafe = append(unsafe, filepath.Base(path)+"="+value)
		}
	}
	if len(vulnerabilities) == 0 {
		checks = append(checks, DoctorCheck{Name: "cpu-vulnerabilities", Detail: "host exposed no CPU vulnerability reports"})
	} else if len(unsafe) != 0 {
		checks = append(checks, DoctorCheck{Name: "cpu-vulnerabilities", Detail: fmt.Sprintf("unmitigated: %s", strings.Join(unsafe, "; "))})
	} else {
		checks = append(checks, DoctorCheck{Name: "cpu-vulnerabilities", OK: true, Detail: fmt.Sprintf("%d host vulnerability reports mitigated/not-affected", len(vulnerabilities))})
	}
	return checks
}

func containsWord(value, expected string) bool {
	for _, word := range strings.Fields(value) {
		if word == expected {
			return true
		}
	}
	return false
}
