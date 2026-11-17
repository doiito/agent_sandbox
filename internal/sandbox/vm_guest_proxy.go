package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const guestProxyVsockPort = 5001

// vmGuestProxy belongs to one physical VM. Its tenant binding is immutable;
// Close joins both the accept loop and every accepted relay before UID reuse.
type vmGuestProxy struct {
	ctx                                 context.Context
	cancel                              context.CancelFunc
	listener                            *net.UnixListener
	directory                           *os.File
	done                                chan struct{}
	workers                             sync.WaitGroup
	closeOnce                           sync.Once
	slots                               chan struct{}
	uid                                 uint32
	egressSocket, tenant, vmID, leaseID string
	inference                           *inferenceBinding
	inferencePolicySHA256               string
}

func newVMGuestProxy(parent context.Context, socketPath, egressSocket, tenant, vmID, leaseID string, uid, gid int, inference ...guestInferenceGrant) (*vmGuestProxy, error) {
	if parent.Err() != nil || !filepath.IsAbs(socketPath) || egressSocket == "" || !safeTenantID(tenant) ||
		!canonicalJobID(vmID) || !canonicalJobID(leaseID) || uid < 1 || gid < 1 {
		return nil, errors.New("invalid VM proxy ownership")
	}
	if len(inference) > 1 || len(inference) == 1 && !inference[0].validFor(tenant, vmID, leaseID) {
		return nil, errors.New("invalid VM inference binding")
	}
	directory, err := os.Open(filepath.Dir(socketPath))
	if err != nil {
		return nil, err
	}
	short := fmt.Sprintf("/proc/self/fd/%d/%s_%d", directory.Fd(), filepath.Base(socketPath), guestProxyVsockPort)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: short})
	if err != nil {
		directory.Close()
		return nil, err
	}
	if err = os.Chmod(short, 0o600); err == nil {
		err = os.Chown(short, uid, gid)
	}
	if err != nil {
		listener.Close()
		directory.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	p := &vmGuestProxy{ctx: ctx, cancel: cancel, listener: listener, directory: directory,
		done: make(chan struct{}), slots: make(chan struct{}, 8), uid: uint32(uid),
		egressSocket: egressSocket, tenant: tenant, vmID: vmID, leaseID: leaseID}
	if len(inference) == 1 {
		copy := inference[0].Binding
		p.inference = &copy
		p.inferencePolicySHA256 = inference[0].PolicySHA256
	}
	go p.serve()
	return p, nil
}

func (p *vmGuestProxy) serve() {
	defer close(p.done)
	stop := context.AfterFunc(p.ctx, func() { _ = p.listener.Close() })
	defer stop()
	for {
		conn, err := p.listener.AcceptUnix()
		if err != nil {
			return
		}
		cred, err := unixPeerCredential(conn)
		if err != nil || cred.Uid != p.uid || p.ctx.Err() != nil {
			conn.Close()
			continue
		}
		select {
		case p.slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		p.workers.Add(1)
		go func() {
			defer p.workers.Done()
			defer func() { <-p.slots }()
			defer conn.Close()
			p.relay(conn)
		}()
	}
}

func (p *vmGuestProxy) Close() {
	p.closeOnce.Do(func() {
		p.cancel()
		_ = p.listener.Close()
		<-p.done // No further workers.Add after this point.
		p.workers.Wait()
		_ = p.directory.Close()
	})
}

func dialGuestProxyEgress(ctx context.Context, socket, tenant, vmID, leaseID string, inference ...guestInferenceGrant) (net.Conn, *bufio.Reader, error) {
	if len(inference) > 1 || len(inference) == 1 && !inference[0].validFor(tenant, vmID, leaseID) {
		return nil, nil, errors.New("invalid guest inference ownership")
	}
	info, err := os.Lstat(socket)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, nil, errors.New("untrusted guest egress socket")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, nil, errors.New("missing egress socket owner")
	}
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, nil, err
	}
	peer, err := unixPeerCredential(conn.(*net.UnixConn))
	if err != nil || peer.Uid != owner.Uid {
		conn.Close()
		return nil, nil, errors.New("guest egress peer owner mismatch")
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline := time.Now().Add(3 * time.Second)
	if bound, ok := ctx.Deadline(); ok && bound.Before(deadline) {
		deadline = bound
	}
	_ = conn.SetDeadline(deadline)
	request, _ := http.NewRequestWithContext(ctx, "POST", "http://egress.invalid/v1/guest-proxy", nil)
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", guestProxyUpgrade)
	request.Header.Set("X-OSV-Tenant", tenant)
	request.Header.Set("X-OSV-VM", vmID)
	request.Header.Set("X-OSV-Lease", leaseID)
	request.Header.Set("X-OSV-Task", leaseID)
	if len(inference) == 1 {
		request.Header.Set("X-OSV-Task", inference[0].Binding.TaskID)
		request.Header.Set("X-OSV-Inference", "remote-infer-v1")
		request.Header.Set("X-OSV-Inference-Policy", inference[0].PolicySHA256)
	}
	if err = request.Write(conn); err != nil {
		conn.Close()
		return nil, nil, err
	}
	reader := bufio.NewReaderSize(conn, guestProxyHeaderLimit)
	// A bounded response parser also preserves any bytes read past the headers.
	response, _, err := readGuestProxyResponse(reader)
	if err != nil {
		conn.Close()
		return nil, nil, errors.New("guest egress upgrade rejected")
	}
	if response.StatusCode != 101 {
		conn.Close()
		switch response.StatusCode {
		case 403:
			return nil, nil, egressError(403, "egress_disabled")
		case 429:
			return nil, nil, egressError(429, "egress_busy")
		default:
			return nil, nil, egressError(503, "egress_unavailable")
		}
	}
	if response.Header.Get("Upgrade") != guestProxyUpgrade || response.Header.Get("Connection") != "Upgrade" {
		conn.Close()
		return nil, nil, errors.New("invalid guest egress upgrade")
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, reader, nil
}

func readGuestProxyResponse(reader *bufio.Reader) (*http.Response, int, error) {
	// Unlike an HTTP body, the upgrade headers must fit entirely within the
	// hard header bound. Peek never discards the subsequent protocol bytes.
	for n := 1; n <= guestProxyHeaderLimit; n++ {
		data, err := reader.Peek(n)
		if err != nil {
			return nil, 0, err
		}
		if n >= 4 && string(data[n-4:]) == "\r\n\r\n" {
			response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), nil)
			if err != nil {
				return nil, 0, err
			}
			_, err = reader.Discard(n)
			return response, n, err
		}
	}
	return nil, 0, errors.New("egress upgrade headers exceed bound")
}

func (p *vmGuestProxy) relay(guest net.Conn) {
	ctx, cancel := context.WithTimeout(p.ctx, 35*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = guest.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	_ = guest.SetDeadline(deadline)
	var binding []guestInferenceGrant
	if p.inference != nil {
		binding = append(binding, guestInferenceGrant{Binding: *p.inference, PolicySHA256: p.inferencePolicySHA256})
	}
	upstream, reader, err := dialGuestProxyEgress(ctx, p.egressSocket, p.tenant, p.vmID, p.leaseID, binding...)
	if err != nil {
		if ctx.Err() == nil {
			var failure *EgressError
			if !errors.As(err, &failure) {
				failure = &EgressError{503, "egress_unavailable"}
			}
			writeGuestProxyError(guest, failure)
		}
		return
	}
	defer upstream.Close()
	_ = upstream.SetDeadline(deadline)
	stopUpstream := context.AfterFunc(ctx, func() { _ = upstream.Close() })
	defer stopUpstream()
	// The egress service enforces tenant-specific limits; this outer transport
	// cap additionally bounds framing and incomplete guest traffic per relay.
	_, _, _ = relayGuestTunnel(guest, guest, &bufferedProxyConn{Conn: upstream, reader: reader}, 1<<20, 1<<20)
}

type bufferedProxyConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedProxyConn) Read(data []byte) (int, error) { return c.reader.Read(data) }

// Called under bootMu, including after a warm claim. Nothing is attached to a
// pristine VM. A failed attachment is fatal to this VM and never returns it.
func (v *vmInstance) startGuestProxy(tenant, leaseID string) error {
	if v.proxy != nil || v.manager.config.Jailer == nil {
		return errors.New("VM proxy already bound or missing jail identity")
	}
	socket, err := jailedFirecrackerVsockPath(v.manager.config.HypervisorPath, v.workdir)
	if err != nil {
		return err
	}
	var inference []guestInferenceGrant
	if v.manager.hasRemoteInferenceFeature() && v.manager.inferenceTenants[tenant] {
		binding := inferenceBinding{Tenant: tenant, TaskID: leaseID, VMID: v.id, LeaseID: leaseID}
		policy := v.manager.inferencePolicyDigest(tenant)
		if !validSHA256Hex(policy) {
			return errors.New("root inference policy snapshot unavailable")
		}
		if err := bindVMInference(v.ctx, v.workdir, v.manager.config.EgressSocket, binding); err != nil {
			return fmt.Errorf("%w: bind VM inference: %v", ErrUnavailable, err)
		}
		inference = append(inference, guestInferenceGrant{Binding: binding, PolicySHA256: policy})
	}
	proxy, err := newVMGuestProxy(v.ctx, socket, v.manager.config.EgressSocket, tenant, v.id, leaseID, v.physical.identity.uid, v.physical.identity.gid, inference...)
	if err != nil {
		return fmt.Errorf("%w: start VM proxy: %v", ErrUnavailable, err)
	}
	v.proxy = proxy
	return nil
}

func (v *vmInstance) bindGuestProxy(tenant, leaseID string) error {
	v.bootMu.Lock()
	defer v.bootMu.Unlock()
	return v.startGuestProxy(tenant, leaseID)
}

func guestProxyBootArg(enabled bool) string {
	if enabled {
		return " agent.proxy=" + strconv.Itoa(guestProxyVsockPort)
	}
	return ""
}
