package sandbox

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestSystemdReadinessDatagram(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("NOTIFY_SOCKET", path)
	if err := NotifySystemdReady(); err != nil {
		t.Fatal(err)
	}
	_ = listener.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 128)
	n, _, err := listener.ReadFromUnix(buffer)
	if err != nil || string(buffer[:n]) != "READY=1" {
		t.Fatalf("readiness notification missing: %q %v", buffer[:n], err)
	}
}

func TestSystemdNotifyDisabledAndInvalidSocket(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := NotifySystemdReady(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NOTIFY_SOCKET", "relative")
	if err := NotifySystemdReady(); err == nil {
		t.Fatal("relative notification path accepted")
	}
}
