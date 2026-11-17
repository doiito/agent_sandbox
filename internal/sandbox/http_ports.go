package sandbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const portTunnelUpgrade = "osv-port/1"

type apiPortTunnel struct {
	cancel context.CancelFunc
	conn   net.Conn // guarded by API.portMu, including late hijack during shutdown
}

func (a *API) registerPortTunnel(t *apiPortTunnel) bool {
	a.portMu.Lock()
	defer a.portMu.Unlock()
	if a.portClosing {
		return false
	}
	if a.portTunnels == nil {
		a.portTunnels = map[*apiPortTunnel]struct{}{}
	}
	a.portTunnels[t] = struct{}{}
	a.portWG.Add(1)
	return true
}

func (a *API) bindPortTunnel(t *apiPortTunnel, conn net.Conn) bool {
	a.portMu.Lock()
	defer a.portMu.Unlock()
	if a.portClosing {
		return false
	}
	t.conn = conn
	return true
}

func (a *API) unregisterPortTunnel(t *apiPortTunnel) {
	a.portMu.Lock()
	delete(a.portTunnels, t)
	a.portMu.Unlock()
	a.portWG.Done()
}

func (a *API) shutdownPortTunnels(ctx context.Context) error {
	a.portMu.Lock()
	a.portClosing = true
	all := make([]*apiPortTunnel, 0, len(a.portTunnels))
	connections := make([]net.Conn, 0, len(a.portTunnels))
	for t := range a.portTunnels {
		all = append(all, t)
		if t.conn != nil {
			connections = append(connections, t.conn)
		}
	}
	a.portMu.Unlock()
	for _, t := range all {
		t.cancel()
	}
	for _, conn := range connections {
		_ = conn.Close()
	}
	done := make(chan struct{})
	go func() { a.portWG.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func validPortUpgrade(r *http.Request) bool {
	if r.ProtoMajor != 1 || r.ProtoMinor != 1 || r.ContentLength < 1 || r.ContentLength > portHandshakeLimit || len(r.TransferEncoding) != 0 {
		return false
	}
	upgrade := r.Header.Values("Upgrade")
	if len(upgrade) != 1 || !strings.EqualFold(strings.TrimSpace(upgrade[0]), portTunnelUpgrade) {
		return false
	}
	for _, line := range r.Header.Values("Connection") {
		for _, token := range strings.Split(line, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

func portHijacker(w http.ResponseWriter) (http.Hijacker, bool) {
	for i := 0; i < 16; i++ {
		if hijacker, ok := w.(http.Hijacker); ok {
			return hijacker, true
		}
		if unwrapper, ok := w.(interface{ Unwrap() http.ResponseWriter }); ok {
			w = unwrapper.Unwrap()
		} else {
			break
		}
	}
	return nil, false
}

func (a *API) portSession(w http.ResponseWriter, r *http.Request) (*apiSession, string, uint16, bool) {
	s := a.lookupSession(r)
	if s == nil {
		writeJobError(w, 404, "not_found", "session not found", true)
		return nil, "", 0, false
	}
	text := r.PathValue("port")
	port, err := strconv.ParseUint(text, 10, 16)
	id := r.PathValue("connection")
	if err != nil || port == 0 || strconv.FormatUint(port, 10) != text || !validSessionID(id) {
		writePortError(w, &PortRequestError{Code: "invalid_request"})
		return nil, "", 0, false
	}
	if !validPortCapability(s) {
		writePortError(w, ErrPortUnsupported)
		return nil, "", 0, false
	}
	return s, id, uint16(port), true
}

func validPortCapability(s *apiSession) bool {
	bound := s.capability
	return bound.Features.PortForward && bound.ArtifactAuthenticated && portManifestProtocol(bound.ArtifactManifestProtocol) &&
		bound.Backend == "firecracker-linux" && bound.Backend == s.info.Backend && validSHA256Hex(bound.ArtifactManifestSHA256) && bound.ArtifactManifestSHA256 == s.info.ArtifactManifestSHA256
}

func (a *API) openPortTunnel(w http.ResponseWriter, r *http.Request) {
	s, id, port, ok := a.portSession(w, r)
	if !ok {
		return
	}
	if !validPortUpgrade(r) {
		status := http.StatusBadRequest
		if r.ProtoMajor != 1 {
			status = http.StatusUpgradeRequired
		}
		w.Header().Set("Upgrade", portTunnelUpgrade)
		writeJobError(w, status, "port_upgrade_required", "use HTTP/1.1 Upgrade: osv-port/1 with bounded JSON limits", true)
		return
	}
	hijacker, ok := portHijacker(w)
	if !ok {
		writeJobError(w, 503, "unavailable", "port transport unavailable", true)
		return
	}
	var limits SessionPortLimits
	if err := decodeHTTPBody(w, r, &limits); err != nil {
		writeJobError(w, 400, "invalid_json", "invalid port limits JSON", true)
		return
	}
	request := SessionPortRequest{ID: id, Port: port, Limits: limits}
	if err := request.validate(); err != nil {
		writePortError(w, err)
		return
	}
	if !s.tenant.allowsTemplate(s.info.Backend, s.info.ArtifactManifestSHA256) || !s.tenant.policy.Ports.allows(port) {
		writePortError(w, &PortRequestError{Code: "denied"})
		return
	}
	if err := s.tenant.consumeRequestToken(); err != nil {
		writePortError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(limits.TimeoutMS)*time.Millisecond)
	defer cancel()
	tunnel := &apiPortTunnel{cancel: cancel}
	if !a.registerPortTunnel(tunnel) {
		writePortError(w, ErrUnavailable)
		return
	}
	defer a.unregisterPortTunnel(tunnel)
	go func() {
		select {
		case <-s.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	p, err := s.handle.OpenPort(ctx, ctx, request)
	if err != nil {
		writePortError(w, err)
		return
	}
	defer p.Close()
	if ctx.Err() != nil {
		return
	}
	conn, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	if !a.bindPortTunnel(tunnel, conn) || ctx.Err() != nil {
		return
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if conn.SetDeadline(time.Time{}) != nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = fmt.Fprintf(buffered, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: %s\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-OSV-Session-ID: %s\r\nX-OSV-Connection-ID: %s\r\nX-OSV-Port: %d\r\n\r\n", portTunnelUpgrade, s.info.ID, id, port)
	if err != nil || buffered.Flush() != nil {
		return
	}
	if conn.SetWriteDeadline(time.Time{}) != nil {
		return
	}
	bridgePortFrames(conn, buffered.Reader, p)
}

func (a *API) portControl(w http.ResponseWriter, r *http.Request, operation string) {
	s, id, port, ok := a.portSession(w, r)
	if !ok {
		return
	}
	info, err := s.handle.PortControl(r.Context(), id, port, operation)
	if err != nil {
		writePortError(w, err)
		return
	}
	status := 200
	if operation == "cancel" {
		status = 202
	}
	writeJSON(w, status, PortConnectionResponse{SessionID: s.info.ID, Connection: info})
}
func (a *API) getPortConnection(w http.ResponseWriter, r *http.Request) { a.portControl(w, r, "info") }
func (a *API) cancelPortConnection(w http.ResponseWriter, r *http.Request) {
	a.portControl(w, r, "cancel")
}

func writePortError(w http.ResponseWriter, err error) {
	code := portRPCError(err).Code
	if errors.Is(err, errPortProtocol) {
		code = "unavailable"
	}
	status := 503
	switch code {
	case "invalid_request", "invalid_binding":
		status = 400
	case "denied":
		status = 403
	case "not_found":
		status = 404
		code = "port_not_found"
	case "conflict", "cancelled":
		status = 409
	case "closed", "expired":
		status = 410
	case "quota":
		status = 429
	case "unsupported":
		status = 501
	case "connection_refused":
		status = 502
	case "timeout", "idle_timeout":
		status = 504
	}
	writeJobError(w, status, code, "port request: "+code, true)
}
