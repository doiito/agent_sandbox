package sandbox

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const previewProtocol = "osv-sandbox-preview/v1"
const previewCookie = "__Host-osv-preview"
const previewAuthorizePath = "/.osv/authorize"
const previewHistoryLimit = 32
const previewSessionLimit = 8
const previewGlobalLimit = 1024
const previewRequestLimit = 16
const previewGlobalRequestLimit = 256
const previewRequestBytes = 8 << 20

type PreviewGrantInfo struct {
	Protocol     string    `json:"protocol"`
	ID           string    `json:"id"`
	SessionID    string    `json:"session_id"`
	Port         uint16    `json:"port"`
	Origin       string    `json:"origin"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Status       string    `json:"status"`
	BootstrapURL string    `json:"bootstrap_url,omitempty"`
}
type previewGrant struct {
	info              PreviewGrantInfo
	host              string
	session           *apiSession
	ctx               context.Context
	cancel            context.CancelFunc
	bootstrap, cookie [32]byte
	authorized        bool
	transport         *http.Transport
	connections       map[*previewConn]struct{}
	requests          map[*previewRequest]struct{}
}
type previewService struct {
	api                        *API
	config                     PreviewConfig
	base                       *url.URL
	mu                         sync.Mutex
	closed                     bool
	grants                     map[string]*previewGrant // random hostname, active grants only
	inflight                   int
	callbacks, handlers, dials sync.WaitGroup
}

func newPreviewService(api *API, config PreviewConfig) (*previewService, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	base, _ := previewHTTPSOrigin(config.OriginBase)
	if base.Port() == "443" {
		base.Host = base.Hostname()
	}
	return &previewService{api: api, config: config, base: base, grants: map[string]*previewGrant{}}, nil
}
func previewSecret() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}
func (p *previewService) create(s *apiSession, id string, port uint16, ttl uint64) (PreviewGrantInfo, error) {
	var info PreviewGrantInfo
	if !validSessionID(id) || ttl < 1000 || ttl > 300000 {
		return info, &PortRequestError{Code: "invalid_request"}
	}
	key, err := randomID()
	if err != nil {
		return info, ErrUnavailable
	}
	secret, err := previewSecret()
	if err != nil {
		return info, ErrUnavailable
	}
	now := time.Now()
	expires := now.Add(time.Duration(ttl) * time.Millisecond)
	s.mu.Lock()
	if s.closing || !now.Before(s.deadline) {
		s.mu.Unlock()
		return info, ErrSessionClosed
	}
	if s.deadline.Before(expires) {
		expires = s.deadline
	}
	s.mu.Unlock()
	origin := *p.base
	origin.Path = ""
	origin.Host = key + "." + p.base.Hostname()
	if p.base.Port() != "" {
		origin.Host += ":" + p.base.Port()
	}
	info = PreviewGrantInfo{Protocol: previewProtocol, ID: id, SessionID: s.info.ID, Port: port, Origin: origin.String(), CreatedAt: now, ExpiresAt: expires, Status: "active"}
	ctx, cancel := context.WithDeadline(context.Background(), expires)
	g := &previewGrant{info: info, host: origin.Host, session: s, ctx: ctx, cancel: cancel, bootstrap: sha256.Sum256([]byte(secret)), connections: map[*previewConn]struct{}{}, requests: map[*previewRequest]struct{}{}}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		cancel()
		return PreviewGrantInfo{}, ErrUnavailable
	}
	if len(p.grants) >= previewGlobalLimit {
		p.mu.Unlock()
		cancel()
		return PreviewGrantInfo{}, &PortRequestError{Code: "quota"}
	}
	if s.previews == nil {
		s.previews = map[string]*previewGrant{}
	}
	active := 0
	for _, old := range s.previews {
		if old.info.Status == "active" {
			active++
		}
	}
	if s.previews[id] != nil {
		p.mu.Unlock()
		cancel()
		return PreviewGrantInfo{}, &PortRequestError{Code: "conflict"}
	}
	if len(s.previews) >= previewHistoryLimit || active >= previewSessionLimit {
		p.mu.Unlock()
		cancel()
		return PreviewGrantInfo{}, &PortRequestError{Code: "quota"}
	}
	s.mu.Lock()
	closed := s.closing
	s.mu.Unlock()
	if closed {
		p.mu.Unlock()
		cancel()
		return PreviewGrantInfo{}, ErrSessionClosed
	}
	g.transport = p.transportFor(g)
	s.previews[id] = g
	p.grants[g.host] = g
	p.callbacks.Add(1)
	p.mu.Unlock()
	context.AfterFunc(ctx, func() {
		defer p.callbacks.Done()
		state := "expired"
		if time.Now().Before(expires) {
			state = "revoked"
		}
		p.revoke(g, state)
	})
	info.BootstrapURL = info.Origin + previewAuthorizePath + "?token=" + secret
	return info, nil
}
func (p *previewService) revoke(g *previewGrant, state string) {
	p.mu.Lock()
	if g.info.Status != "active" {
		p.mu.Unlock()
		return
	}
	g.info.Status = state
	delete(p.grants, g.host)
	connections := make([]*previewConn, 0, len(g.connections))
	for c := range g.connections {
		connections = append(connections, c)
	}
	requests := make([]*previewRequest, 0, len(g.requests))
	for r := range g.requests {
		requests = append(requests, r)
	}
	p.mu.Unlock()
	g.cancel()
	g.transport.CloseIdleConnections()
	for _, r := range requests {
		r.cancel()
	}
	for _, c := range connections {
		_ = c.Close()
	}
}
func (p *previewService) closeSession(s *apiSession) {
	p.mu.Lock()
	all := make([]*previewGrant, 0, len(s.previews))
	for _, g := range s.previews {
		all = append(all, g)
	}
	p.mu.Unlock()
	for _, g := range all {
		p.revoke(g, "session_closed")
	}
}
func (p *previewService) shutdown(ctx context.Context) error {
	p.mu.Lock()
	p.closed = true
	all := make([]*previewGrant, 0, len(p.grants))
	for _, g := range p.grants {
		all = append(all, g)
	}
	p.mu.Unlock()
	for _, g := range all {
		p.revoke(g, "server_closed")
	}
	done := make(chan struct{})
	go func() { p.callbacks.Wait(); p.handlers.Wait(); p.dials.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (p *previewService) lookup(s *apiSession, id string) (*previewGrant, bool) {
	p.mu.Lock()
	g := s.previews[id]
	p.mu.Unlock()
	if g == nil {
		return nil, false
	}
	if !time.Now().Before(g.info.ExpiresAt) {
		p.revoke(g, "expired")
	}
	return g, true
}
func (a *API) previewOwner(w http.ResponseWriter, r *http.Request) (*apiSession, string, bool) {
	s := a.lookupSession(r)
	if s == nil {
		writeJobError(w, 404, "not_found", "session not found", true)
		return nil, "", false
	}
	id := r.PathValue("preview")
	if !validSessionID(id) {
		writePortError(w, &PortRequestError{Code: "invalid_request"})
		return nil, "", false
	}
	if a.preview == nil || !validPortCapability(s) {
		writePortError(w, ErrPortUnsupported)
		return nil, "", false
	}
	return s, id, true
}
func (a *API) createPreview(w http.ResponseWriter, r *http.Request) {
	s, id, ok := a.previewOwner(w, r)
	if !ok {
		return
	}
	text := r.PathValue("port")
	port, err := strconv.ParseUint(text, 10, 16)
	if err != nil || port == 0 || strconv.Itoa(int(port)) != text {
		writePortError(w, &PortRequestError{Code: "invalid_request"})
		return
	}
	var request PreviewCreateRequest
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if r.ContentLength > 4096 || decodeHTTPBody(w, r, &request) != nil || request.TTLMS < 1000 || request.TTLMS > 300000 {
		writePortError(w, &PortRequestError{Code: "invalid_request"})
		return
	}
	policy := s.tenant.policy.Ports
	if policy == nil || !policy.Preview || !policy.allows(uint16(port)) || !s.tenant.allowsTemplate(s.info.Backend, s.info.ArtifactManifestSHA256) {
		writePortError(w, &PortRequestError{Code: "denied"})
		return
	}
	if err := s.tenant.consumeRequestToken(); err != nil {
		writePortError(w, err)
		return
	}
	info, err := a.preview.create(s, id, uint16(port), request.TTLMS)
	if err != nil {
		writePortError(w, err)
		return
	}
	writeJSON(w, 201, info)
}
func (a *API) previewControl(w http.ResponseWriter, r *http.Request, revoke bool) {
	s, id, ok := a.previewOwner(w, r)
	if !ok {
		return
	}
	g, exists := a.preview.lookup(s, id)
	if !exists {
		writeJobError(w, 404, "preview_not_found", "preview grant not found", true)
		return
	}
	if revoke {
		a.preview.revoke(g, "revoked")
	}
	a.preview.mu.Lock()
	info := g.info
	a.preview.mu.Unlock()
	writeJSON(w, 200, info)
}
func (a *API) getPreview(w http.ResponseWriter, r *http.Request)    { a.previewControl(w, r, false) }
func (a *API) revokePreview(w http.ResponseWriter, r *http.Request) { a.previewControl(w, r, true) }

func (p *previewService) authenticate(w http.ResponseWriter, r *http.Request) (*previewGrant, bool) {
	if r.TLS == nil || r.URL.IsAbs() {
		writeJobError(w, 400, "invalid_preview_origin", "HTTPS origin-form required", true)
		return nil, false
	}
	host := strings.ToLower(r.Host)
	// Browsers omit default :443. No other forwarded host/port aliases are used.
	if p.base.Port() == "" && strings.HasSuffix(host, ":443") {
		host = strings.TrimSuffix(host, ":443")
	}
	p.mu.Lock()
	g := p.grants[host]
	p.mu.Unlock()
	if g == nil {
		writeJobError(w, 404, "preview_not_found", "preview unavailable", true)
		return nil, false
	}
	if !time.Now().Before(g.info.ExpiresAt) || g.session.expired() {
		p.revoke(g, "expired")
		writeJobError(w, 410, "preview_expired", "preview expired", true)
		return nil, false
	}
	policy := g.session.tenant.policy.Ports
	if policy == nil || !policy.Preview || !policy.allows(g.info.Port) || !g.session.tenant.allowsTemplate(g.session.info.Backend, g.session.info.ArtifactManifestSHA256) {
		p.revoke(g, "revoked")
		writeJobError(w, 403, "preview_denied", "preview unavailable", true)
		return nil, false
	}
	if r.URL.Path == previewAuthorizePath {
		query, err := url.ParseQuery(r.URL.RawQuery)
		if r.Method != "GET" || err != nil || len(query) != 1 || len(query["token"]) != 1 || !validSHA256Hex(query.Get("token")) {
			writeJobError(w, 400, "invalid_preview_bootstrap", "invalid bootstrap request", true)
			return nil, false
		}
		digest := sha256.Sum256([]byte(query.Get("token")))
		cookie, err := previewSecret()
		if err != nil {
			writePortError(w, ErrUnavailable)
			return nil, false
		}
		p.mu.Lock()
		valid := g.info.Status == "active" && !g.authorized && subtle.ConstantTimeCompare(g.bootstrap[:], digest[:]) == 1
		if valid {
			g.authorized = true
			g.bootstrap = [32]byte{}
			g.cookie = sha256.Sum256([]byte(cookie))
		}
		p.mu.Unlock()
		if !valid {
			writeJobError(w, 401, "preview_unauthorized", "bootstrap unavailable", true)
			return nil, false
		}
		http.SetCookie(w, &http.Cookie{Name: previewCookie, Value: cookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: g.info.ExpiresAt, MaxAge: int(time.Until(g.info.ExpiresAt).Seconds())})
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Location", "/")
		w.WriteHeader(http.StatusSeeOther)
		return nil, false
	}
	if strings.HasPrefix(r.URL.Path, "/.osv/") {
		writeJobError(w, 404, "not_found", "reserved preview path", true)
		return nil, false
	}
	var auth *http.Cookie
	for _, cookie := range r.Cookies() {
		if cookie.Name == previewCookie {
			if auth != nil {
				writeJobError(w, 401, "preview_unauthorized", "ambiguous cookie", true)
				return nil, false
			}
			auth = cookie
		}
	}
	if auth == nil || !validSHA256Hex(auth.Value) {
		writeJobError(w, 401, "preview_unauthorized", "preview authorization required", true)
		return nil, false
	}
	digest := sha256.Sum256([]byte(auth.Value))
	p.mu.Lock()
	valid := g.authorized && g.info.Status == "active" && subtle.ConstantTimeCompare(g.cookie[:], digest[:]) == 1
	p.mu.Unlock()
	if !valid {
		writeJobError(w, 401, "preview_unauthorized", "preview authorization required", true)
		return nil, false
	}
	if origin := r.Header.Get("Origin"); len(r.Header.Values("Origin")) > 1 || origin != "" && origin != g.info.Origin {
		writeJobError(w, 403, "preview_origin_denied", "cross-origin preview request denied", true)
		return nil, false
	}
	return g, true
}
