package sandbox

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type EgressServiceConfig struct {
	Inference      *InferenceServiceConfig `json:"inference,omitempty"`
	GuestProxy     bool                    `json:"guest_proxy,omitempty"`
	Production     bool                    `json:"production"`
	SocketPath     string                  `json:"socket_path"`
	AuthPolicyPath string                  `json:"auth_policy_path"`
	AuditLogPath   string                  `json:"audit_log_path"`
	CAFile         string                  `json:"ca_file,omitempty"`
	MaxConcurrent  int                     `json:"max_concurrent,omitempty"`
}

func LoadEgressConfig(path string) (EgressServiceConfig, error) {
	var config EgressServiceConfig
	f, err := os.Open(path)
	if err != nil {
		return config, errors.New("cannot open egress config")
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, 1<<20))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return config, errors.New("invalid egress config")
	}
	if config.MaxConcurrent == 0 {
		config.MaxConcurrent = 16
	}
	if config.MaxConcurrent < 1 || config.MaxConcurrent > 64 {
		return config, errors.New("egress max_concurrent must be in [1,64]")
	}
	if err := validateInferenceServiceConfig(config.Inference, config.Production, config.GuestProxy); err != nil {
		return config, err
	}
	for _, p := range []string{config.SocketPath, config.AuthPolicyPath, config.AuditLogPath} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return config, errors.New("egress paths must be canonical and absolute")
		}
	}
	if config.Production {
		for _, p := range []string{path, config.AuthPolicyPath} {
			if err := trustedProductionConfigPath(p); err != nil {
				return config, err
			}
		}
		if config.CAFile != "" {
			if err := trustedProductionConfigPath(config.CAFile); err != nil {
				return config, err
			}
		}
	}
	return config, nil
}

type EgressAuditEvent struct {
	TaskID        string               `json:"task_id,omitempty"`
	Endpoint      string               `json:"endpoint,omitempty"`
	Inference     *InferenceAuditMeter `json:"inference,omitempty"`
	VMID          string               `json:"vm_id,omitempty"`
	LeaseID       string               `json:"lease_id,omitempty"`
	Protocol      string               `json:"protocol"`
	At            time.Time            `json:"at"`
	Event         string               `json:"event"`
	RequestID     string               `json:"request_id"`
	Tenant        string               `json:"tenant"`
	Origin        string               `json:"origin,omitempty"`
	Method        string               `json:"method,omitempty"`
	IP            string               `json:"ip,omitempty"`
	Hop           int                  `json:"hop,omitempty"`
	Code          string               `json:"code,omitempty"`
	Status        int                  `json:"status,omitempty"`
	RequestBytes  int                  `json:"request_bytes,omitempty"`
	ResponseBytes int                  `json:"response_bytes,omitempty"`
	DurationMS    int64                `json:"duration_ms,omitempty"`
}
type EgressAuditRecorder interface {
	AppendNetwork(EgressAuditEvent) error
	Err() error
}

func (a *AuditLog) AppendNetwork(event EgressAuditEvent) error {
	event.Protocol, event.At = "osv-sandbox-egress-audit/v1", time.Now().UTC()
	return a.appendRecord(event)
}
func OpenEgressAudit(path string) (*AuditLog, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("invalid egress audit path")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("egress audit parent must be a private managed directory")
	}
	if st, ok := parent.Sys().(*syscall.Stat_t); !ok || st.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("egress audit directory must be owned by service user")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		f.Close()
		return nil, errors.New("egress audit must be a private regular file")
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Uid != uint32(os.Geteuid()) {
		f.Close()
		return nil, errors.New("egress audit must be service owned")
	}
	if err = validateAuditTail(f); err != nil {
		f.Close()
		return nil, err
	}
	return &AuditLog{writer: f, sync: f.Sync, file: f}, nil
}

type EgressServer struct {
	GuestProxy            bool
	proxyMu               sync.Mutex
	proxyClosing          bool
	proxyConnections      map[net.Conn]context.CancelFunc
	proxyWG               sync.WaitGroup
	proxyInferenceIngress int
	proxyInferenceTenants map[*tenantRuntime]int
	auth                  *Authenticator
	audit                 EgressAuditRecorder
	engine                *egressEngine
	inference             *inferenceEngine
	slots                 chan struct{}
	mu                    sync.Mutex
	active                int
}

func NewEgressServer(auth *Authenticator, audit EgressAuditRecorder, caFile string, maximum int) (*EgressServer, error) {
	if auth == nil || audit == nil || maximum < 1 || maximum > 64 {
		return nil, errors.New("invalid egress server dependencies")
	}
	var roots *x509.CertPool
	if caFile != "" {
		data, err := os.ReadFile(caFile)
		if err != nil {
			return nil, errors.New("cannot read egress CA")
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			return nil, errors.New("invalid egress CA")
		}
	}
	return &EgressServer{auth: auth, audit: audit, engine: newEgressEngine(roots), slots: make(chan struct{}, maximum)}, nil
}
func (s *EgressServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if strings.HasPrefix(r.URL.Path, "/v1/inference/root/") {
		s.serveInferenceRoot(w, r, false)
		return
	}
	if r.URL.Path == "/v1/guest-proxy" {
		s.guestProxyUpgrade(w, r)
		return
	}
	tenant, ok := s.auth.Authenticate(r.Header.Get("Authorization"))
	if !ok {
		writeJobError(w, 401, "unauthorized", "unauthorized", true)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v1/inference/") {
		s.serveInferenceQuery(w, r, tenant)
		return
	}
	if tenant.egress == nil {
		writeJobError(w, 403, "egress_disabled", "egress disabled for tenant", true)
		return
	}
	if s.audit.Err() != nil {
		writeJobError(w, 503, "egress_audit", "egress audit unavailable", true)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/v1/policy" {
		writeJSON(w, 200, map[string]any{"protocol": "osv-sandbox-egress-policy/v1", "policy": tenant.egress.policy, "guest_proxy": s.GuestProxy})
		return
	}
	if r.Method != "POST" || r.URL.Path != "/v1/fetch" {
		writeJobError(w, 404, "not_found", "not found", true)
		return
	}
	requestID, err := randomID()
	if err != nil {
		writeJobError(w, 503, "unavailable", "request identity unavailable", true)
		return
	}
	started := time.Now()
	record := EgressAuditEvent{RequestID: requestID, Tenant: tenant.policy.ID, Event: "net.deny"}
	var result NetworkFetchResult
	completionPersisted := false
	defer func() {
		if completionPersisted {
			return
		}
		record.DurationMS = time.Since(started).Milliseconds()
		record.RequestBytes = result.RequestBytes
		record.ResponseBytes = result.ResponseBytes
		if err := s.audit.AppendNetwork(record); err != nil {
			return
		}
	}()
	var request NetworkFetchRequest
	if err = decodeHTTPBody(w, r, &request); err != nil {
		record.Code = "egress_request"
		writeJobError(w, 400, record.Code, "invalid bounded network request", true)
		return
	}
	if _, origin, e := egressURL(request.URL); e == nil {
		record.Origin = origin
	}
	method := request.Method
	if method == "" {
		method = "GET"
	}
	if len(method) <= 16 {
		record.Method = method
	}
	if err = tenant.consumeRequestToken(); err != nil {
		record.Code = "egress_rate_limit"
		writeJobError(w, 429, record.Code, "network request rate limit", true)
		return
	}
	select {
	case tenant.netSem <- struct{}{}:
		defer func() { <-tenant.netSem }()
	default:
		record.Code = "egress_busy"
		writeJobError(w, 429, record.Code, "tenant network concurrency limit", true)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		record.Code = "egress_busy"
		writeJobError(w, 429, record.Code, "global network concurrency limit", true)
		return
	}
	if s.audit.AppendNetwork(EgressAuditEvent{RequestID: requestID, Tenant: tenant.policy.ID, Event: "net.admit", Origin: record.Origin, Method: record.Method}) != nil {
		record.Code = "egress_audit"
		writeJobError(w, 503, record.Code, "network audit unavailable", true)
		return
	}
	s.mu.Lock()
	s.active++
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.active--; s.mu.Unlock() }()
	result, err = s.engine.fetch(r.Context(), request, tenant.egress, func(origin, method, ip string, hop int) error {
		if s.audit.AppendNetwork(EgressAuditEvent{RequestID: requestID, Tenant: tenant.policy.ID, Event: "net.allow", Origin: origin, Method: method, IP: ip, Hop: hop}) != nil {
			return egressError(503, "egress_audit")
		}
		return nil
	})
	if err != nil {
		var failure *EgressError
		if !errors.As(err, &failure) {
			failure = &EgressError{502, "egress_upstream"}
		}
		record.Code = failure.Code
		writeJobError(w, failure.Status, failure.Code, failure.Error(), true)
		return
	}
	result.RequestID = requestID
	record.Event = "net.complete"
	record.Status = result.Status
	// Persist completion before returning a successful network result.
	record.DurationMS = time.Since(started).Milliseconds()
	record.RequestBytes = result.RequestBytes
	record.ResponseBytes = result.ResponseBytes
	if err = s.audit.AppendNetwork(record); err != nil {
		record.Code = "egress_audit"
		writeJobError(w, 503, record.Code, "network completion audit failed", true)
		return
	}
	completionPersisted = true
	writeJSON(w, 200, result)
}

type egressListener struct {
	*net.UnixListener
	uid         uint32
	allowRoot   bool
	connections chan struct{}
}
type egressConn struct {
	*net.UnixConn
	uid     uint32
	once    sync.Once
	release func()
}

func (c *egressConn) Close() error { err := c.UnixConn.Close(); c.once.Do(c.release); return err }
func (l *egressListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		cred, err := unixPeerCredential(conn)
		if err != nil || (cred.Uid != l.uid && (!l.allowRoot || cred.Uid != 0)) {
			conn.Close()
			continue
		}
		select {
		case l.connections <- struct{}{}:
			return &egressConn{UnixConn: conn, uid: cred.Uid, release: func() { <-l.connections }}, nil
		default:
			conn.Close()
		}
	}
}
func listenEgressSocket(path string) (*net.UnixListener, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("invalid egress socket path")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("egress socket requires private service-owned directory")
	}
	if st, ok := parent.Sys().(*syscall.Stat_t); !ok || st.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("egress socket directory owner mismatch")
	}
	if info, e := os.Lstat(path); e == nil {
		if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("unexpected egress socket target")
		}
		if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Uid != uint32(os.Geteuid()) {
			return nil, errors.New("egress socket owner mismatch")
		}
		if conn, e := net.DialTimeout("unix", path, 100*time.Millisecond); e == nil {
			conn.Close()
			return nil, errors.New("egress socket already active")
		}
		if err = os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: path})
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func egressPeerContext(ctx context.Context, conn net.Conn) context.Context {
	if peer, ok := conn.(*egressConn); ok {
		return context.WithValue(ctx, egressPeerKey{}, peer.uid)
	}
	return ctx
}

func ServeEgress(ctx context.Context, path string, server *EgressServer) error {
	if server == nil || server.inference != nil && inferenceControlSocketPath(path) == path {
		return errors.New("invalid or conflicting egress service sockets")
	}
	listener, err := listenEgressSocket(path)
	if err != nil {
		return err
	}
	defer listener.Close()
	wrapped := &egressListener{UnixListener: listener, uid: uint32(os.Geteuid()), allowRoot: server.GuestProxy, connections: make(chan struct{}, 64)}
	service := &http.Server{Handler: server, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	service.ConnContext = egressPeerContext
	shutdown, stop := context.WithCancel(ctx)
	defer stop()
	var control *http.Server
	var controlWrapped *egressListener
	controlDone := make(chan error, 1)
	if server.inference != nil {
		controlListener, err := listenEgressSocket(inferenceControlSocketPath(path))
		if err != nil {
			return err
		}
		defer controlListener.Close()
		controlWrapped = &egressListener{UnixListener: controlListener, uid: 0, connections: make(chan struct{}, 64)}
		control = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			server.serveInferenceRoot(w, r, true)
		}), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 8 * time.Second,
			IdleTimeout: time.Second, MaxHeaderBytes: 8192, ConnContext: egressPeerContext,
			BaseContext: func(net.Listener) context.Context { return ctx }}
		go func() {
			controlDone <- control.Serve(controlWrapped)
			stop()
		}()
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-shutdown.Done()
		server.closeGuestProxies()
		if server.inference != nil {
			server.inference.Close()
		}
		deadline, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if control != nil && control.Shutdown(deadline) != nil {
			_ = control.Close()
		}
		if service.Shutdown(deadline) != nil {
			_ = service.Close()
		}
	}()
	err = service.Serve(wrapped)
	stop()
	<-stopped
	var controlErr error
	if control != nil {
		controlErr = <-controlDone
		if errors.Is(controlErr, http.ErrServerClosed) {
			controlErr = nil
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return errors.Join(err, controlErr)
}
