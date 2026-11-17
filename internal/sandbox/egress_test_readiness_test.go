package sandbox

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestEgressTestSocketReadinessRequiresListening(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-yet-listening.sock")
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: path}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("bind must expose the path before listen", err)
	}
	if egressTestSocketAccepting(path) {
		t.Fatal("a bound but not listening socket was accepted as ready")
	}
	if err := syscall.Listen(fd, 1); err != nil {
		t.Fatal(err)
	}
	if !egressTestSocketAccepting(path) {
		t.Fatal("a genuinely listening socket was not ready")
	}
}
