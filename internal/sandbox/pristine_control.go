package sandbox

import (
	"bufio"
	"context"
	"errors"
	"net"
	"time"
)

const (
	pristineControlMaxIdle           = 2 * time.Second
	pristineControlArmTimeout        = time.Second
	pristineControlMaintenanceMargin = 500 * time.Millisecond
)

var errPristineControlUnavailable = errors.New("pristine control connection unavailable")

// One already-negotiated, empty connection belongs to one VM. It is consumed
// by exactly one ping or prepare; a new frame never reuses an old connection.
type pristineControlConnection struct {
	owner      *vmInstance
	socketPath string
	port       uint32
	conn       net.Conn
	reader     *bufio.Reader
	expiresAt  time.Time
	stopOwner  func() bool
}

func (c *pristineControlConnection) close() {
	if c.stopOwner != nil {
		c.stopOwner()
	}
	_ = c.conn.Close()
}

// Caller owns the unpublished VM or holds controlMu. The handshake contains
// no tenant data. Its short cancellation is detached before publication;
// the lifetime callback closes only the captured connection, never a new one.
func (v *vmInstance) armPristineControl(ctx context.Context, backend FirecrackerLinuxBackend) error {
	if ctx.Err() != nil || v.ctx.Err() != nil || v.idleControl.Load() != nil {
		return errPristineControlUnavailable
	}
	socketPath, err := backend.vsockPath(v.workdir)
	if err != nil {
		return err
	}
	arm, cancel := context.WithTimeout(ctx, pristineControlArmTimeout)
	defer cancel()
	conn, reader, stopClosing, err := dialFirecrackerVsock(arm, socketPath, backend.Guest.VsockPort)
	if err != nil {
		return err
	}
	if !stopClosing() || arm.Err() != nil || v.ctx.Err() != nil {
		_ = conn.Close()
		return errPristineControlUnavailable
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return err
	}
	control := &pristineControlConnection{owner: v, socketPath: socketPath, port: backend.Guest.VsockPort,
		conn: conn, reader: reader, expiresAt: time.Now().Add(pristineControlMaxIdle)}
	control.stopOwner = context.AfterFunc(v.ctx, func() { _ = conn.Close() })
	if !v.idleControl.CompareAndSwap(nil, control) {
		control.close()
		return errPristineControlUnavailable
	}
	if ctx.Err() != nil || v.ctx.Err() != nil {
		v.idleControl.CompareAndSwap(control, nil)
		control.close()
		return errPristineControlUnavailable
	}
	return nil
}

// This method is a dial replacement, so any error is strictly before a
// prepare payload write. The shared session transport alone classifies it.
func (v *vmInstance) takePristineControl(ctx context.Context, socketPath string, port uint32) (net.Conn, *bufio.Reader, func() bool, error) {
	return v.takePristineControlAt(ctx, socketPath, port, time.Now())
}

func (v *vmInstance) takePristineControlAt(ctx context.Context, socketPath string, port uint32, now time.Time) (net.Conn, *bufio.Reader, func() bool, error) {
	control := v.idleControl.Swap(nil)
	if control == nil {
		return nil, nil, nil, errPristineControlUnavailable
	}
	if control.owner != v {
		// An invalid reference cannot acquire or close another VM's resource.
		return nil, nil, nil, errPristineControlUnavailable
	}
	if control.socketPath != socketPath || control.port != port ||
		!now.Before(control.expiresAt) || ctx.Err() != nil || v.ctx.Err() != nil {
		control.close()
		return nil, nil, nil, errPristineControlUnavailable
	}
	if !control.stopOwner() {
		_ = control.conn.Close()
		return nil, nil, nil, errPristineControlUnavailable
	}
	deadline, _ := ctx.Deadline()
	if err := control.conn.SetDeadline(deadline); err != nil {
		_ = control.conn.Close()
		return nil, nil, nil, err
	}
	conn := control.conn
	stopClosing := context.AfterFunc(ctx, func() { _ = conn.Close() })
	if ctx.Err() != nil || v.ctx.Err() != nil {
		stopClosing()
		_ = conn.Close()
		return nil, nil, nil, errPristineControlUnavailable
	}
	return conn, control.reader, stopClosing, nil
}

// Destroy must close an idle connection synchronously, even when it already
// holds controlMu or a cancellation callback is still waiting to run.
func (v *vmInstance) closePristineControl() {
	if control := v.idleControl.Swap(nil); control != nil && control.owner == v {
		control.close()
	}
}

func (v *vmInstance) pristineControlNeedsMaintenance(now time.Time) bool {
	control := v.idleControl.Load()
	return control != nil && control.owner == v && !now.Before(control.expiresAt.Add(-pristineControlMaintenanceMargin))
}

func (p *warmPool) preconnectedLinux() (linuxPristineVMBackend, bool) {
	backend, ok := p.backend.(linuxPristineVMBackend)
	return backend, ok && p.config.HealthIntervalMS > 0 && p.config.HealthIntervalMS <= 1000
}
