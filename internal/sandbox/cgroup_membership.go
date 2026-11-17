package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const cgroupMemberLimit = 16 << 10

// Verify live membership in the expected dedicated domain, without the global
// hierarchy lock used by /proc/PID/cgroup on supported Linux kernels. Process
// generation/liveness and lease ownership are separately checked by the caller.
func verifyPristineCgroup(jailer *JailerConfig, pid int, workdir string) error {
	if jailer == nil {
		return nil
	}
	instance := filepath.Base(workdir)
	if !safeCgroupName(jailer.ParentCgroup) || !validJobInstanceID(instance) {
		return errors.New("invalid pristine cgroup identity")
	}
	return verifyCgroupMembershipDirectory(filepath.Join("/sys/fs/cgroup", jailer.ParentCgroup, instance), pid)
}

func verifyCgroupMembershipDirectory(path string, pid int) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var fs syscall.Statfs_t
	if err := syscall.Fstatfs(fd, &fs); err != nil {
		return err
	}
	if fs.Type != 0x63677270 { // CGROUP2_SUPER_MAGIC
		return errors.New("pristine cgroup directory is not cgroup v2")
	}
	return verifyDomainMemberAt(fd, pid)
}

func verifyDomainMemberAt(fd, pid int) error {
	return verifyDomainMember(pid, func(name string, limit int) ([]byte, error) {
		return readCgroupEntryAt(fd, name, limit)
	})
}

func verifyDomainMember(pid int, read func(string, int) ([]byte, error)) error {
	typeBefore, err := read("cgroup.type", 64)
	if err != nil {
		return err
	}
	if string(typeBefore) != "domain\n" {
		return errors.New("pristine cgroup is not a direct domain")
	}
	data, err := read("cgroup.procs", cgroupMemberLimit)
	if err != nil {
		return err
	}
	if err := validatePristineMembers(data, pid); err != nil {
		return err
	}
	// A threaded domain's list can aggregate descendants. Never accept that
	// interpretation, including a type change while enumerating membership.
	typeAfter, err := read("cgroup.type", 64)
	if err != nil {
		return err
	}
	if string(typeAfter) != "domain\n" {
		return errors.New("pristine cgroup type changed")
	}
	return nil
}

func validatePristineMembers(data []byte, pid int) error {
	return validatePristineMembersWithWorkers(data, pid, verifyPristineKernelWorker)
}

func validatePristineMembersWithWorkers(data []byte, pid int, worker func(int) error) error {
	if pid <= 1 || uint64(pid) > 1<<31-1 || len(data) == 0 || len(data) > cgroupMemberLimit || data[len(data)-1] != '\n' {
		return errors.New("invalid pristine cgroup member list")
	}
	found := false
	extra := make(map[int]struct{})
	for _, member := range strings.Split(string(data[:len(data)-1]), "\n") {
		value, err := strconv.ParseUint(member, 10, 31)
		if err != nil || value <= 1 || strconv.FormatUint(value, 10) != member {
			return errors.New("invalid pristine cgroup member PID")
		}
		if int(value) == pid {
			found = true
		} else {
			extra[int(value)] = struct{}{}
		}
	}
	if !found {
		return errors.New("pristine VM is not a direct cgroup member")
	}
	// KVM attaches its kernel workers to the VM's cgroup. They remain within
	// the existing resource/cleanup budget. Never trust a userspace comm name
	// or UID as evidence of a kernel worker, and do not skip unknown members.
	for member := range extra {
		if err := worker(member); err != nil {
			return err
		}
	}
	return nil
}

func verifyPristineKernelWorker(pid int) error {
	if pid <= 1 || uint64(pid) > 1<<31-1 {
		return errors.New("invalid pristine worker PID")
	}
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return err
	}
	return verifyPristineKernelWorkerStat(data, pid)
}

func verifyPristineKernelWorkerStat(data []byte, pid int) error {
	opening, closing := strings.IndexByte(string(data), '('), strings.LastIndexByte(string(data), ')')
	if len(data) == 0 || len(data) > 4096 || data[len(data)-1] != '\n' || opening < 1 || closing <= opening ||
		strings.TrimSpace(string(data[:opening])) != strconv.Itoa(pid) {
		return errors.New("malformed pristine kernel worker stat")
	}
	fields := strings.Fields(string(data[closing+1:]))
	if len(fields) < 20 || len(fields[0]) != 1 || !strings.ContainsAny(fields[0], "RSDTtKWPI") {
		return errors.New("pristine kernel worker is not live")
	}
	flags, err := strconv.ParseUint(fields[6], 10, 64)
	if err != nil || strconv.FormatUint(flags, 10) != fields[6] || flags&0x00200000 == 0 { // PF_KTHREAD, set by the kernel.
		return errors.New("unexpected userspace process in pristine cgroup")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || strconv.FormatUint(ticks, 10) != fields[19] {
		return errors.New("malformed pristine kernel worker generation")
	}
	return nil
}

// All entries are read relative to one pinned directory. Direct syscalls keep
// these synchronous, bounded kernel-file reads outside the network poller.
func readCgroupEntryAt(directory int, name string, limit int) ([]byte, error) {
	if (name != "cgroup.type" && name != "cgroup.procs") || limit < 1 || limit > cgroupMemberLimit {
		return nil, errors.New("invalid cgroup read")
	}
	fd, err := syscall.Openat(directory, name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	data := make([]byte, 0, min(limit+1, 128))
	var chunk [256]byte
	for {
		n, err := syscall.Read(fd, chunk[:min(len(chunk), limit+1-len(data))])
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return data, nil
		}
		data = append(data, chunk[:n]...)
		if len(data) > limit {
			return nil, errors.New("cgroup entry exceeds read bound")
		}
	}
}
