package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestPristineMemberParsing(t *testing.T) {
	for _, data := range []string{"123\n", "123\n123\n"} {
		if err := validatePristineMembers([]byte(data), 123); err != nil {
			t.Fatal(err)
		}
	}
	for _, data := range []string{"", "123", "0123\n", "+123\n", " 123\n", "123\r\n", "123\n456\n", "123\n\n", "0\n", strings.Repeat("123\n", 5000)} {
		if err := validatePristineMembersWithWorkers([]byte(data), 123, func(int) error { return errors.New("unexpected worker") }); err == nil {
			t.Fatalf("invalid list accepted: %q", data[:min(len(data), 30)])
		}
	}
	for _, pid := range []int{0, 1, -1, 1 << 31} {
		if err := validatePristineMembers([]byte("123\n"), pid); err == nil {
			t.Fatal("invalid process identity accepted")
		}
	}
}

func TestPristineMemberKernelWorkerAllowance(t *testing.T) {
	calls := 0
	worker := func(pid int) error {
		calls++
		if pid != 456 {
			return errors.New("not a verified worker")
		}
		return nil
	}
	if err := validatePristineMembersWithWorkers([]byte("456\n123\n456\n123\n"), 123, worker); err != nil || calls != 1 {
		t.Fatal("verified duplicate worker rejected or not deduplicated", err, calls)
	}
	for _, data := range []string{"456\n", "123\n456\nbad\n", "123\n0123\n"} {
		calls = 0
		if err := validatePristineMembersWithWorkers([]byte(data), 123, worker); err == nil || calls != 0 {
			t.Fatal("missing VM or malformed list reached worker checks", err, calls)
		}
	}
	for _, errWorker := range []error{syscall.ENOENT, syscall.EPERM, errors.New("bad stat")} {
		if err := validatePristineMembersWithWorkers([]byte("123\n456\n"), 123, func(int) error { return errWorker }); err == nil {
			t.Fatal("unknown worker accepted")
		}
	}
	expected := os.Getpid() + 1
	if err := validatePristineMembers([]byte(fmt.Sprintf("%d\n%d\n", expected, os.Getpid())), expected); err == nil {
		t.Fatal("real userspace process accepted as kernel worker")
	}
}

func TestPristineMemberWorkerParsing(t *testing.T) {
	stat := func(pid int, name, state, flags string) []byte {
		fields := strings.Fields("S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 7")
		fields[0], fields[6] = state, flags
		return []byte(fmt.Sprintf("%d (%s) %s\n", pid, name, strings.Join(fields, " ")))
	}
	if err := verifyPristineKernelWorkerStat(stat(456, "kernel (worker)", "S", "2129984"), 456); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{stat(456, "kvm-nx-lpage-recovery-123", "S", "0"),
		stat(457, "kernel", "S", "2129984"), stat(456, "kernel", "Z", "2129984"),
		stat(456, "kernel", "X", "2129984"), stat(456, "kernel", "S", "bad"),
		[]byte("456 (kernel) S\n"), []byte("456 malformed\n"), []byte(strings.Repeat("x", 4097))} {
		if err := verifyPristineKernelWorkerStat(data, 456); err == nil {
			t.Fatal("forged, dead or malformed kernel worker accepted")
		}
	}
	valid := stat(456, "kernel", "S", "2129984")
	if err := verifyPristineKernelWorkerStat(valid[:len(valid)-1], 456); err == nil {
		t.Fatal("truncated kernel stat accepted")
	}
	if err := verifyPristineKernelWorker(os.Getpid()); err == nil {
		t.Fatal("real user process classified as kernel thread")
	}
}

func TestPristineMemberDirectoryAndReadBound(t *testing.T) {
	root := t.TempDir()
	write := func(name, data string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("cgroup.type", "domain\n")
	write("cgroup.procs", "123\n")
	// Ordinary files can exercise the reader/parser, never the production
	// filesystem guard. A convincing fake cgroup on a normal FS must fail.
	if err := verifyCgroupMembershipDirectory(root, 123); err == nil {
		t.Fatal("ordinary filesystem accepted as cgroup v2")
	}
	directory, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	fd := int(directory.Fd())
	if err := verifyDomainMemberAt(fd, 123); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"threaded\n", "domain threaded\n", "domain invalid\n", "domain", ""} {
		write("cgroup.type", kind)
		if err := verifyDomainMemberAt(fd, 123); err == nil {
			t.Fatalf("invalid type accepted: %q", kind)
		}
	}
	write("cgroup.type", "domain\n")
	write("cgroup.procs", strings.Repeat("123\n", 5000))
	if _, err := readCgroupEntryAt(fd, "cgroup.procs", cgroupMemberLimit); err == nil {
		t.Fatal("oversized member read accepted")
	}
	write("cgroup.type", strings.Repeat("x", 65))
	if _, err := readCgroupEntryAt(fd, "cgroup.type", 64); err == nil {
		t.Fatal("oversized type read accepted")
	}
	for _, name := range []string{"../cgroup.procs", "/cgroup.procs", "other"} {
		if _, err := readCgroupEntryAt(fd, name, 64); err == nil {
			t.Fatal("unsafe entry accepted")
		}
	}
	for _, limit := range []int{0, -1, cgroupMemberLimit + 1} {
		if _, err := readCgroupEntryAt(fd, "cgroup.procs", limit); err == nil {
			t.Fatal("invalid read bound accepted")
		}
	}
}

func TestPristineMemberReaderPinsDirectoryAndRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	leaf := filepath.Join(root, "leaf")
	if err := os.Mkdir(leaf, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(path, data string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(leaf, "cgroup.type"), "domain\n")
	write(filepath.Join(leaf, "cgroup.procs"), "123\n")
	directory, err := os.Open(leaf)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err := os.Rename(leaf, leaf+"-pinned"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(leaf, 0700); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(leaf, "cgroup.type"), "domain\n")
	write(filepath.Join(leaf, "cgroup.procs"), "456\n")
	if err := verifyDomainMemberAt(int(directory.Fd()), 123); err != nil {
		t.Fatal("reader followed replacement directory:", err)
	}
	if err := os.Remove(filepath.Join(leaf+"-pinned", "cgroup.procs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(leaf, "cgroup.procs"), filepath.Join(leaf+"-pinned", "cgroup.procs")); err != nil {
		t.Fatal(err)
	}
	if _, err := readCgroupEntryAt(int(directory.Fd()), "cgroup.procs", cgroupMemberLimit); err != syscall.ELOOP {
		t.Fatal("symlink entry not rejected:", err)
	}
	if err := os.Symlink(leaf, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := verifyCgroupMembershipDirectory(filepath.Join(root, "alias"), 456); err == nil {
		t.Fatal("symlink directory accepted")
	}
}

func TestPristineMemberTypeChangeOrReadFailureCannotPass(t *testing.T) {
	for _, last := range []string{"domain threaded\n", "threaded\n", ""} {
		reads := 0
		err := verifyDomainMember(123, func(name string, limit int) ([]byte, error) {
			reads++
			if reads == 1 {
				return []byte("domain\n"), nil
			}
			if name == "cgroup.procs" {
				return []byte("123\n"), nil
			}
			if last == "" {
				return nil, syscall.ENODEV
			}
			return []byte(last), nil
		})
		if err == nil || reads != 3 {
			t.Fatal("type change/read failure accepted", err, reads)
		}
	}
}

func TestPristineMemberReadErrorsDoNotLeakDescriptors(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "cgroup.procs"), 0700); err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for range 256 {
		if _, err := readCgroupEntryAt(int(directory.Fd()), "cgroup.procs", cgroupMemberLimit); err == nil {
			t.Fatal("directory read accepted")
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("descriptor leak: before=%d after=%d", len(before), len(after))
	}
}
