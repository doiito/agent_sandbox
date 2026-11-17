package sandbox

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type firecrackerVsockDial func(context.Context, string, uint32) (net.Conn, *bufio.Reader, func() bool, error)

// dialFirecrackerVsock completes Firecracker's UDS CONNECT negotiation. The
// opened parent directory keeps a long, trusted jail path short for sockaddr_un.
func dialFirecrackerVsock(ctx context.Context, socketPath string, port uint32) (net.Conn, *bufio.Reader, func() bool, error) {
	socketDir, err := os.Open(filepath.Dir(socketPath))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open jailed vsock directory: %w", err)
	}
	defer socketDir.Close()
	dialPath := fmt.Sprintf("/proc/self/fd/%d/%s", socketDir.Fd(), filepath.Base(socketPath))
	dialer := net.Dialer{Timeout: 25 * time.Millisecond}
	for {
		conn, err := dialer.DialContext(ctx, "unix", dialPath)
		if err == nil {
			active := conn
			stopClosing := context.AfterFunc(ctx, func() { _ = active.Close() })
			if deadline, ok := ctx.Deadline(); ok {
				_ = conn.SetDeadline(deadline)
			}
			reader := bufio.NewReaderSize(conn, 128)
			if _, err = fmt.Fprintf(conn, "CONNECT %d\n", port); err == nil {
				var ack []byte
				ack, err = reader.ReadSlice('\n')
				if err == nil {
					assigned, parseErr := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(string(ack), "OK "), "\n"), 10, 32)
					if strings.HasPrefix(string(ack), "OK ") && parseErr == nil && assigned > 0 {
						return conn, reader, stopClosing, nil
					}
					err = errors.New("invalid guest vsock acknowledgement")
				}
			}
			stopClosing()
			_ = conn.Close()
		}
		select {
		case <-ctx.Done():
			return nil, nil, nil, fmt.Errorf("connect guest vsock: %w (last error: %v)", ctx.Err(), err)
		case <-time.After(2 * time.Millisecond):
		}
	}
}

func jailedFirecrackerVsockPath(hypervisorPath, workdir string) (string, error) {
	absoluteWorkdir, err := filepath.Abs(workdir)
	if err != nil {
		return "", err
	}
	instanceID := filepath.Base(absoluteWorkdir)
	return filepath.Join(absoluteWorkdir, "jailer", filepath.Base(hypervisorPath), instanceID, "root", "agent.vsock"), nil
}
