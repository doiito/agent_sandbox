package sandbox

import (
	"context"
	"errors"
	"sync"
	"time"
)

const sessionPortActiveLimit = 8
const sessionPortHistoryLimit = 256

type SessionPortRequest struct {
	ID     string            `json:"id"`
	Port   uint16            `json:"port"`
	Limits SessionPortLimits `json:"limits"`
}

func (r SessionPortRequest) validate() error {
	if !validSessionID(r.ID) || r.Port == 0 || !r.Limits.valid() {
		return &PortRequestError{Code: "invalid_request"}
	}
	return nil
}

type sessionPortRecord struct {
	id              string
	port            uint16
	limits          SessionPortLimits
	active          bool
	cancelRequested bool
	terminal        *SessionPortInfo
	transport       *linuxPortStream
	cancel          context.CancelFunc
	release         func()
	done            chan struct{}
	reconcileOnce   sync.Once
	onFinish        func(*SessionPortInfo)
}

type sessionPortStream struct {
	session   *Session
	record    *sessionPortRecord
	transport *linuxPortStream
}

func clonePortInfo(info SessionPortInfo) SessionPortInfo {
	if info.Error != nil {
		code := *info.Error
		info.Error = &code
	}
	return info
}

func (s *Session) portAvailable() error {
	if !s.manager.hasLinuxPortFeature() || !s.backend.PortForward {
		return ErrPortUnsupported
	}
	if s.info.Backend != s.manager.config.Backend || s.info.ArtifactManifestSHA256 != s.manager.manifest.digestSHA256 {
		return ErrPortUnsupported
	}
	if s.closed.Load() || s.ctx.Err() != nil || s.instance.ctx.Err() != nil {
		return ErrSessionClosed
	}
	s.lifecycleMu.Lock()
	lease, hard := s.leaseDeadline, s.hardDeadline
	s.lifecycleMu.Unlock()
	if !lease.IsZero() && !time.Now().Before(lease) || !hard.IsZero() && !time.Now().Before(hard) {
		return ErrSessionClosed
	}
	return nil
}

// The launcher supplies its independently loaded tenant runtime after checking
// the Unix peer. Caller-supplied policy fields never enter this method.
func (s *Session) openSessionPort(ctx context.Context, request SessionPortRequest, tenant *tenantRuntime) (*sessionPortStream, error) {
	if err := s.portAvailable(); err != nil {
		return nil, err
	}
	if err := request.validate(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if tenant == nil {
		return nil, &PortRequestError{Code: "denied"}
	}
	owned, err := s.manager.ownedSession(s.info.ID, tenant.policy.ID)
	if err != nil || owned != s {
		return nil, ErrSessionClosed
	}
	if !tenant.allowsTemplate(s.info.Backend, s.info.ArtifactManifestSHA256) {
		return nil, &PortRequestError{Code: "denied"}
	}
	release, err := tenant.acquirePort(request.Port)
	if err != nil {
		return nil, err
	}
	s.portsMu.Lock()
	if s.closed.Load() || s.ctx.Err() != nil {
		s.portsMu.Unlock()
		release()
		return nil, ErrSessionClosed
	}
	if old := s.ports[request.ID]; old != nil {
		code := "conflict"
		if old.port != request.Port {
			code = "invalid_binding"
		} else if old.cancelRequested {
			code = "cancelled"
		}
		s.portsMu.Unlock()
		release()
		return nil, &PortRequestError{Code: code}
	}
	active := 0
	for _, r := range s.ports {
		if r.active {
			active++
		}
	}
	if active >= sessionPortActiveLimit || len(s.ports) >= sessionPortHistoryLimit {
		s.portsMu.Unlock()
		release()
		return nil, &PortRequestError{Code: "quota"}
	}
	lifetime, cancel := context.WithCancel(s.ctx)
	record := &sessionPortRecord{id: request.ID, port: request.Port, limits: request.Limits, active: true,
		cancel: cancel, release: release, done: make(chan struct{})}
	if s.ports == nil {
		s.ports = map[string]*sessionPortRecord{}
	}
	s.ports[request.ID] = record
	s.portsMu.Unlock()
	identity, err := newLinuxGuestBinding(s.info.ID)
	if err != nil {
		s.finishPortRecord(record, nil) // no guest request was submitted
		return nil, err
	}
	wire := linuxPortRequest{SessionID: s.info.ID, Nonce: identity.Nonce, Binding: s.binding,
		Operation: "open", ID: request.ID, Port: request.Port, Limits: &request.Limits}
	transport, err := s.backend.openPort(ctx, lifetime, wire, s.workdir)
	if err != nil {
		cancel()
		var typed *PortRequestError
		if errors.As(err, &typed) && (typed.Code == "connection_refused" || typed.Code == "timeout" || typed.Code == "io_error" || typed.Code == "quota") {
			// A bound guest error ACK proves this open did not leave a TCP
			// descriptor. Keep the ID reserved, including failed admission.
			s.finishPortRecord(record, nil)
		} else {
			s.reconcilePort(record)
		}
		if errors.Is(err, errPortProtocol) {
			go func() { _ = s.Close() }()
		}
		return nil, err
	}
	s.portsMu.Lock()
	record.transport = transport
	interrupted := !record.active || record.cancelRequested || s.closed.Load() || lifetime.Err() != nil
	s.portsMu.Unlock()
	stream := &sessionPortStream{s, record, transport}
	if interrupted {
		stream.Close()
		return nil, &PortRequestError{Code: "cancelled"}
	}
	return stream, nil
}

// All record fields except reconcileOnce are guarded by portsMu. Releasing
// tenant capacity is outside that lock and happens only once, after proof.
func (s *Session) finishPortRecord(r *sessionPortRecord, info *SessionPortInfo) {
	s.portsMu.Lock()
	if !r.active {
		s.portsMu.Unlock()
		return
	}
	r.active = false
	if info != nil {
		copy := clonePortInfo(*info)
		r.terminal = &copy
	}
	release, cancel, observe := r.release, r.cancel, r.onFinish
	r.release = nil
	r.cancel = nil
	r.transport = nil
	r.onFinish = nil
	close(r.done)
	s.portsMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if observe != nil {
		observe(info)
	}
	if release != nil {
		release()
	}
}

func (p *sessionPortStream) observeFinish(observe func(*SessionPortInfo)) {
	p.session.portsMu.Lock()
	active := p.record.active
	var info *SessionPortInfo
	if active {
		p.record.onFinish = observe
	} else if p.record.terminal != nil {
		copy := clonePortInfo(*p.record.terminal)
		info = &copy
	}
	p.session.portsMu.Unlock()
	if !active {
		observe(info)
	}
}

func (s *Session) portGuestControl(ctx context.Context, r *sessionPortRecord, operation string) (SessionPortInfo, error) {
	identity, err := newLinuxGuestBinding(s.info.ID)
	if err != nil {
		return SessionPortInfo{}, err
	}
	info, err := s.backend.exchangePortControl(ctx, s.ctx, linuxPortRequest{SessionID: s.info.ID, Nonce: identity.Nonce,
		Binding: s.binding, Operation: operation, ID: r.id, Port: r.port}, s.workdir)
	if err == nil && info.validate(r.id, r.port, r.limits.MaxBytes) != nil {
		return SessionPortInfo{}, errPortProtocol
	}
	return info, err
}

func (s *Session) sessionPortControl(ctx context.Context, id string, port uint16, operation string) (SessionPortInfo, error) {
	if err := s.portAvailable(); err != nil {
		return SessionPortInfo{}, err
	}
	if !validSessionID(id) || port == 0 || operation != "cancel" && operation != "info" {
		return SessionPortInfo{}, &PortRequestError{Code: "invalid_request"}
	}
	s.portsMu.Lock()
	r := s.ports[id]
	if r == nil {
		if operation == "info" {
			s.portsMu.Unlock()
			return SessionPortInfo{}, &PortRequestError{Code: "not_found"}
		}
		if len(s.ports) >= sessionPortHistoryLimit {
			s.portsMu.Unlock()
			return SessionPortInfo{}, &PortRequestError{Code: "quota"}
		}
		code := "cancelled"
		info := SessionPortInfo{ID: id, Port: port, Status: "cancelled", Error: &code}
		done := make(chan struct{})
		close(done)
		r = &sessionPortRecord{id: id, port: port, cancelRequested: true, terminal: &info, done: done}
		if s.ports == nil {
			s.ports = map[string]*sessionPortRecord{}
		}
		s.ports[id] = r
	}
	if r.port != port {
		s.portsMu.Unlock()
		return SessionPortInfo{}, &PortRequestError{Code: "invalid_binding"}
	}
	if r.terminal != nil {
		info := clonePortInfo(*r.terminal)
		s.portsMu.Unlock()
		return info, nil
	}
	if operation == "cancel" {
		r.cancelRequested = true
	}
	transport, cancel := r.transport, r.cancel
	s.portsMu.Unlock()
	if operation == "cancel" {
		if cancel != nil {
			cancel()
		}
		if transport != nil {
			transport.Close()
		}
		s.reconcilePort(r)
	}
	info, err := s.portGuestControl(ctx, r, operation)
	if err == nil && info.terminal() {
		s.finishPortRecord(r, &info)
	}
	if errors.Is(err, errPortProtocol) {
		go func() { _ = s.Close() }()
	}
	return info, err
}

func (s *Session) reconcilePort(r *sessionPortRecord) {
	r.reconcileOnce.Do(func() {
		go func() {
			ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
			defer cancel()
			operation := "cancel"
			for {
				s.portsMu.Lock()
				active := r.active
				s.portsMu.Unlock()
				if !active || s.closed.Load() {
					return
				}
				info, err := s.portGuestControl(ctx, r, operation)
				if err == nil && info.terminal() {
					s.finishPortRecord(r, &info)
					return
				}
				if err == nil {
					operation = "info"
				}
				select {
				case <-ctx.Done():
					// Close runs after this worker returns; it must never wait
					// for itself while joining/retiring the owning VM.
					if !s.closed.Load() {
						go func() { _ = s.Close() }()
					}
					return
				case <-time.After(25 * time.Millisecond):
				}
			}
		}()
	})
}

func (p *sessionPortStream) Write(data []byte) (int, error) {
	n, err := p.transport.Write(data)
	if err != nil {
		var typed *PortRequestError
		if !errors.As(err, &typed) {
			p.Close()
		}
	}
	return n, err
}

func (p *sessionPortStream) CloseWrite() error {
	err := p.transport.CloseWrite()
	if err != nil {
		p.Close()
	}
	return err
}

func (p *sessionPortStream) Next() (linuxPortFrame, error) {
	frame, err := p.transport.Next()
	if frame.Info != nil {
		p.session.finishPortRecord(p.record, frame.Info)
	}
	if err != nil {
		p.Close()
		if errors.Is(err, errPortProtocol) {
			go func() { _ = p.session.Close() }()
		}
	}
	return frame, err
}

func (p *sessionPortStream) Close() {
	p.transport.Close()
	p.session.portsMu.Lock()
	cancel := p.record.cancel
	p.session.portsMu.Unlock()
	if cancel != nil {
		cancel()
	}
	p.session.reconcilePort(p.record)
}

func (s *Session) closePortTransports() {
	s.portsMu.Lock()
	var transports []*linuxPortStream
	var cancels []context.CancelFunc
	for _, r := range s.ports {
		if r.transport != nil {
			transports = append(transports, r.transport)
		}
		if r.cancel != nil {
			cancels = append(cancels, r.cancel)
		}
	}
	s.portsMu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	for _, transport := range transports {
		transport.Close()
	}
}

func (s *Session) finishPortsAfterDestroy() {
	s.portsMu.Lock()
	all := make([]*sessionPortRecord, 0, len(s.ports))
	for _, r := range s.ports {
		all = append(all, r)
	}
	s.portsMu.Unlock()
	for _, r := range all {
		s.finishPortRecord(r, nil)
	}
}
