package sandbox

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// NotifySystemdReady is sent by the service main process only after all
// prerequisites, including the Unix listener and durable audit, are ready.
func NotifySystemdReady() error {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) && (!strings.HasPrefix(path, "@") || len(path) < 2) {
		return errors.New("NOTIFY_SOCKET must be an absolute or abstract Unix socket")
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, err = conn.Write([]byte("READY=1"))
	return err
}
