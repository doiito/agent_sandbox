// This init is used only in the QEMU ARM64 release protocol test.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func mcpProbe(root string) bool {
	path := filepath.Join(root, "bin/osv-sandbox-mcp")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Old signed rollback packages predate MCP.
		return true
	}
	data, err := os.ReadFile("/mcp/mcp.json")
	var config map[string]any
	if err != nil || json.Unmarshal(data, &config) != nil {
		fmt.Println("FAIL bundled-mcp-stdio: fixture configuration")
		return false
	}
	for _, key := range []string{"ca_file", "cert_file", "key_file", "token_file"} {
		config[key] = "/mcp/" + filepath.Base(config[key].(string))
	}
	data, _ = json.Marshal(config)
	if os.WriteFile("/mcp/mcp.json", data, 0o600) != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, path, "-config", "/mcp/mcp.json")
	input, err := command.StdinPipe()
	if err != nil {
		return false
	}
	output, err := command.StdoutPipe()
	if err != nil {
		return false
	}
	command.Stderr = os.Stderr
	if err = command.Start(); err != nil {
		fmt.Println("FAIL bundled-mcp-stdio:", err)
		return false
	}
	reader := bufio.NewReader(output)
	exchange := func(request string) map[string]any {
		if _, err = fmt.Fprintln(input, request); err != nil {
			return nil
		}
		line, e := reader.ReadBytes('\n')
		var response struct {
			Result map[string]any `json:"result"`
		}
		if e != nil || json.Unmarshal(line, &response) != nil {
			return nil
		}
		return response.Result
	}
	modern := exchange(`{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`)
	legacy := exchange(`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"qemu-offline","version":"1"}}}`)
	_, _ = fmt.Fprintln(input, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	ping := exchange(`{"jsonrpc":"2.0","id":3,"method":"ping"}`)
	_ = input.Close()
	err = command.Wait()
	if modern["resultType"] != "complete" || legacy["protocolVersion"] != "2025-11-25" || ping == nil || err != nil {
		fmt.Println("FAIL bundled-mcp-stdio:", err)
		return false
	}
	fmt.Println("PASS bundled-mcp-stdio")
	return true
}

func run(label, name string, args ...string) bool {
	command := exec.Command(name, args...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		fmt.Printf("FAIL %s: %v\n", label, err)
		return false
	}
	fmt.Printf("PASS %s\n", label)
	return true
}

func mountAgentWorkspace() error {
	_ = os.MkdirAll("/w", 0o755)
	if _, err := os.Stat("/modules/loop.ko"); err != nil {
		return syscall.Mount("tmpfs", "/w", "tmpfs", 0, "size=64m")
	}
	for _, name := range []string{"crc32c_generic", "crc16", "mbcache", "jbd2", "ext4", "loop"} {
		data, err := os.ReadFile("/modules/" + name + ".ko")
		if err != nil {
			return err
		}
		params, _ := syscall.BytePtrFromString("")
		_, _, errno := syscall.Syscall(syscall.SYS_INIT_MODULE, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(params)))
		runtime.KeepAlive(data)
		runtime.KeepAlive(params)
		if errno != 0 && errno != syscall.EEXIST {
			return fmt.Errorf("load %s: %w", name, errno)
		}
	}
	if err := syscall.Mknod("/dev/loop0", syscall.S_IFBLK|0o600, 7<<8); err != nil && err != syscall.EEXIST {
		return err
	}
	loop, err := os.OpenFile("/dev/loop0", os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer loop.Close()
	image, err := os.OpenFile("/tmp/mkfs-test.ext4", os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer image.Close()
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, loop.Fd(), 0x4c00, image.Fd())
	if errno != 0 {
		return errno
	}
	if err := syscall.Mount("/dev/loop0", "/w", "ext4", 0, ""); err != nil {
		return err
	}
	fmt.Println("PASS agent-work-ext4")
	return nil
}

func main() {
	_ = os.MkdirAll("/dev", 0o755)
	if err := syscall.Mount("devtmpfs", "/dev", "devtmpfs", 0, ""); err != nil {
		fmt.Println("devtmpfs:", err)
	}
	fmt.Println("ARM64_QEMU_TEST_BEGIN")
	_ = os.MkdirAll("/proc", 0o755)
	if err := syscall.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		fmt.Println("FAIL proc-mount:", err)
		return
	}
	for name, target := range map[string]string{"/dev/fd": "/proc/self/fd", "/dev/stdin": "/proc/self/fd/0", "/dev/stdout": "/proc/self/fd/1", "/dev/stderr": "/proc/self/fd/2"} {
		if err := os.Symlink(target, name); err != nil {
			fmt.Println("FAIL standard-fd-link:", err)
			return
		}
	}
	if err := os.MkdirAll("/tmp", 0o755); err != nil {
		fmt.Println(err)
	}
	ok := run("release-verify", "/bin/osv-offline-release", "verify", "-archive", "/release.tar", "-public-key", "/release.public", "-arch", "arm64")
	ok = run("release-install", "/bin/osv-offline-release", "install", "-archive", "/release.tar", "-public-key", "/release.public", "-root", "/tmp/versions") && ok
	if _, err := os.Stat("/tmp/versions"); err == nil {
		entries, err := os.ReadDir("/tmp/versions")
		if err == nil && len(entries) == 1 {
			root := filepath.Join("/tmp/versions", entries[0].Name())
			ok = mcpProbe(root) && ok
			ok = egressProbe(root) && ok
			ok = inferenceTemplateProbe(root) && ok
			ok = ociTemplateProbe(root) && ok
			if fileExists("/bin/otlp-installed") {
				ok = run("bundled-otlp-api", "/bin/otlp-installed", "-root", root, "-fixtures", "/mcp", "-work", "/otlp-installed", "-output", "/otlp-installed-result.json") && ok
			}
			wantBytes, wantErr := os.ReadFile("/sdk.sha256")
			sdkBytes, sdkErr := os.ReadFile(filepath.Join(root, "sdk/python/osv_sandbox_client.py"))
			want := strings.Fields(string(wantBytes))
			sdkSum := sha256.Sum256(sdkBytes)
			if wantErr == nil && sdkErr == nil && len(want) > 0 &&
				hex.EncodeToString(sdkSum[:]) == want[0] {
				fmt.Println("PASS bundled-sdk")
			} else {
				fmt.Printf("FAIL bundled-sdk: expected=%v read=%v\n", wantErr, sdkErr)
				ok = false
			}
			nodeWantBytes, nodeWantErr := os.ReadFile("/node-sdk.sha256")
			nodeBytes, nodeErr := os.ReadFile(filepath.Join(root, "sdk/node/index.js"))
			nodeWant := strings.Fields(string(nodeWantBytes))
			nodeSum := sha256.Sum256(nodeBytes)
			if nodeWantErr == nil && nodeErr == nil && len(nodeWant) > 0 &&
				hex.EncodeToString(nodeSum[:]) == nodeWant[0] {
				fmt.Println("PASS bundled-node-sdk")
			} else {
				fmt.Printf("FAIL bundled-node-sdk: expected=%v read=%v\n", nodeWantErr, nodeErr)
				ok = false
			}
			loader := filepath.Join(root, "lib/ld-linux-aarch64.so.1")
			if _, err := os.Stat(loader); err == nil {
				image := "/tmp/mkfs-test.ext4"
				file, err := os.Create(image)
				if err == nil {
					err = file.Truncate(32 << 20)
					_ = file.Close()
				}
				if err == nil {
					ok = run("bundled-mkfs", loader, "--library-path", filepath.Join(root, "lib"),
						filepath.Join(root, "bin/mkfs.ext4"), "-q", "-F", "-O", "^has_journal", image) && ok
				} else {
					fmt.Println("FAIL bundled-mkfs:", err)
					ok = false
				}
			}
		}
	}
	if err := mountAgentWorkspace(); err != nil {
		fmt.Println("FAIL agent-work-mount:", err)
		ok = false
	} else {
		_ = os.Setenv("TMPDIR", "/w")
	}
	ok = run("agent-protocol", "/bin/agent-tests", "--exact", "tests::validates_protocol_and_job_id") && ok
	ok = run("agent-vsock-accept-deadlines", "/bin/agent-tests", "vsock_accept_tests::", "--test-threads=1") && ok
	ok = run("musl-mimalloc", "/bin/allocator-tests", "--test-threads=1") && ok
	ok = run("agent-pristine-state", "/bin/agent-tests", "pristine::tests::", "--skip", "pristine::tests::pristine_real_readonly_mount") && ok
	_ = os.Setenv("OSV_PRISTINE_MOUNT_TEST", "1")
	ok = run("agent-pristine-readonly-mount", "/bin/agent-tests", "--ignored", "--exact", "pristine::tests::pristine_real_readonly_mount") && ok
	_ = os.Unsetenv("OSV_PRISTINE_MOUNT_TEST")
	ok = run("host-capacity-ledger", "/bin/capacity-tests", "-test.run=^TestCapacity", "-test.count=1") && ok
	ok = run("host-template-catalog-shared-pools", "/bin/capacity-tests", "-test.run=^Test(Catalog|TemplateCatalog)", "-test.count=1", "-test.timeout=45s") && ok
	ok = run("host-mcp-protocol-tools-lifecycle", "/bin/mcp-tests", "-test.count=1", "-test.timeout=30s") && ok
	ok = run("host-egress-policy-http-tls-unix", "/bin/capacity-tests", "-test.run=^TestEgress", "-test.count=1", "-test.timeout=30s") && ok
	ok = run("host-inference-v7-root-ledger", "/bin/capacity-tests", "-test.run=^TestInference", "-test.count=1", "-test.timeout=180s") && ok
	ok = run("host-otlp-api", "/bin/capacity-tests", "-test.run=^TestOTLP", "-test.count=1", "-test.timeout=60s") && ok
	ok = run("host-cold-startup-mode", "/bin/capacity-tests", "-test.run=^Test(ManagerRunsAndCapturesOutput|ManagerAcceptsBoundResultBeforeExpectedVMMShutdown|ManagerKillsTimedOutVM|ControlChannelIsCompletionAuthority)$", "-test.count=1", "-test.timeout=60s") && ok
	ok = run("host-guest-proxy-vm-identity-tls-lifecycle", "/bin/capacity-tests", "-test.run=^Test(GuestProxy|VMProxy|SignedLinuxProxy)", "-test.count=1", "-test.timeout=45s") && ok
	ok = run("agent-loopback-proxy-relay", "/bin/agent-tests", "network_proxy::tests::", "--skip", "network_proxy::tests::qemu_loopback_ioctl_and_vsock_failure_are_bounded") && ok
	_ = os.Setenv("OSV_GUEST_PROXY_IOCTL_TEST", "1")
	ok = run("agent-proxy-arm64-ioctl-vsock", "/bin/agent-tests", "--ignored", "--exact", "network_proxy::tests::qemu_loopback_ioctl_and_vsock_failure_are_bounded") && ok
	_ = os.Unsetenv("OSV_GUEST_PROXY_IOCTL_TEST")
	ok = run("host-vm-owner", "/bin/capacity-tests", "-test.run=^TestVMOwner", "-test.count=1", "-test.timeout=30s") && ok
	ok = run("host-session-liveness", "/bin/capacity-tests", "-test.run=^TestSession(Query|RenewableLease|PreparationHard|ListStable|APITimeout)", "-test.count=1", "-test.timeout=30s") && ok
	ok = run("host-warm-pool", "/bin/capacity-tests", "-test.run=^TestWarmPool", "-test.count=1", "-test.timeout=60s") && ok
	ok = run("host-atomic-warm-pool", "/bin/capacity-tests", "-test.run=^TestAtomicWarm", "-test.count=1", "-test.timeout=60s") && ok
	ok = run("host-cgroup-membership", "/bin/capacity-tests", "-test.run=^TestPristineMember(Parsing|DirectoryAndReadBound|ReaderPinsDirectoryAndRejectsSymlink|TypeChangeOrReadFailureCannotPass|ReadErrorsDoNotLeakDescriptors|KernelWorkerAllowance|WorkerParsing)$", "-test.count=1", "-test.timeout=30s") && ok
	ok = run("host-pristine-prepare-transport", "/bin/capacity-tests", "-test.run=^Test(VsockCancellationInterruptsAckAndResult|OSvPristineControlDoesNotRetryOrIgnoreCancellation|StreamedBackendInputAcknowledgementsAndCancel|CommandInputJournalBoundsAndLifecycle|LinuxJobExecutionInputsAdmissionAndWire)$", "-test.count=1", "-test.timeout=30s") && ok
	ok = run("host-create-disconnect", "/bin/capacity-tests", "-test.run=^TestSessionCreateDisconnect", "-test.count=1", "-test.timeout=30s") && ok
	ok = run("agent-fixed-job-stdin", "/bin/agent-tests", "fixed_job_stdin") && ok
	ok = run("agent-bounds", "/bin/agent-tests", "--exact", "tests::rejects_unbounded_output") && ok
	ok = run("agent-session-ping", "/bin/agent-tests", "--exact", "tests::session_ping_keeps_guest_alive_and_shutdown_powers_off") && ok
	ok = run("agent-session-invalid", "/bin/agent-tests", "--exact", "tests::malformed_session_request_cannot_shutdown_guest") && ok
	ok = run("agent-session-ttl", "/bin/agent-tests", "--exact", "tests::expired_session_rejects_request_and_powers_off") && ok
	ok = run("agent-session-frame", "/bin/agent-tests", "--exact", "tests::oversized_frame_is_rejected_without_executing") && ok
	ok = run("agent-file-roundtrip", "/bin/agent-tests", "--exact", "tests::workspace_file_roundtrip_is_binary_and_atomic") && ok
	ok = run("agent-file-confinement", "/bin/agent-tests", "--exact", "tests::workspace_file_rejects_traversal_and_symlink_escape") && ok
	ok = run("agent-file-metadata", "/bin/agent-tests", "--exact", "tests::workspace_file_list_stat_delete_are_bounded_and_confined") && ok
	ok = run("agent-file-info-binding", "/bin/agent-tests", "--exact", "tests::file_info_remains_bound_to_open_inode_during_replacement") && ok
	ok = run("agent-file-list-limit", "/bin/agent-tests", "--exact", "tests::workspace_file_list_refuses_more_than_256_names") && ok
	ok = run("agent-file-mkdir", "/bin/agent-tests", "--exact", "tests::workspace_directory_creation_is_confined_and_idempotent") && ok
	ok = run("agent-command-streaming", "/bin/agent-tests", "streaming::tests::") && ok
	ok = run("bash-language", "/bin/bash", "--noprofile", "--norc", "-c", `a=(alpha beta); declare -A m=([key]=value); [[ ${a[1]} == beta && ${m[key]} == value ]] || exit 4; read -r value < <(printf 'process\n'); [[ $value == process ]] || exit 5; printf 'BASH_STATIC_LANGUAGE_PASS %s %.3f\n' "$BASH_VERSION" 3.125`) && ok
	ok = run("agent-file-tree-mutations", "/bin/agent-tests", "workspace_mutations::tests::") && ok
	ok = run("agent-directory-watch-inotify", "/bin/agent-tests", "file_watch::") && ok
	ok = run("host-directory-watch-control", "/bin/capacity-tests", "-test.run=^TestDirectoryWatch", "-test.count=1", "-test.timeout=30s") && ok
	ok = run("mcp-directory-watch", "/bin/mcp-tests", "-test.run=^TestDirectoryWatch", "-test.count=1", "-test.timeout=30s") && ok
	result := "ARM64_QEMU_TEST_FAIL"
	if ok {
		result = "ARM64_QEMU_TEST_PASS"
	}
	fmt.Println(result)
	_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	for {
		syscall.Pause()
	}
}
