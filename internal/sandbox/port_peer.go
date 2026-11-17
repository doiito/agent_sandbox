package sandbox

import (
	"context"
	"net"
	"os"
	"sync"
	"syscall"
)

// Only watch transport loss. A read-based disconnect probe would consume the
// first DATA byte when the client pipelines frames with the JSON handshake.
func watchPortPeerClose(conn *net.UnixConn, cancel context.CancelFunc) (func(), error) {
	poller, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if err != nil {
		return nil, err
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		_ = syscall.Close(poller)
		return nil, err
	}
	var installErr error
	err = raw.Control(func(fd uintptr) {
		installErr = syscall.EpollCtl(poller, syscall.EPOLL_CTL_ADD, int(fd), &syscall.EpollEvent{
			Events: syscall.EPOLLRDHUP | syscall.EPOLLHUP | syscall.EPOLLERR, Fd: int32(fd),
		})
	})
	if err != nil || installErr != nil {
		_ = syscall.Close(poller)
		if err != nil {
			return nil, err
		}
		return nil, installErr
	}
	wake, signal, err := os.Pipe()
	if err != nil {
		_ = syscall.Close(poller)
		return nil, err
	}
	wakeFD := int(wake.Fd())
	if err = syscall.EpollCtl(poller, syscall.EPOLL_CTL_ADD, wakeFD, &syscall.EpollEvent{Events: syscall.EPOLLIN | syscall.EPOLLHUP, Fd: int32(wakeFD)}); err != nil {
		_ = wake.Close()
		_ = signal.Close()
		_ = syscall.Close(poller)
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer syscall.Close(poller)
		defer wake.Close()
		var events [1]syscall.EpollEvent
		for {
			n, err := syscall.EpollWait(poller, events[:], 25)
			if err == syscall.EINTR {
				continue
			}
			if n > 0 && int(events[0].Fd) == wakeFD {
				return
			}
			if err != nil || n > 0 {
				cancel()
				return
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { _ = signal.Close(); <-done }) }, nil
}
