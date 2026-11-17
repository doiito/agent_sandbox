package sandbox

import "errors"

type registeredSession struct {
	tenant  string
	session *Session
}

// The catalog owner provides one lookup for independent, authenticated control
// RPCs. The original owner connection still controls each session's lifetime.
func (m *Manager) registerOwnedSession(s *Session, tenant string) error {
	root := m.lifecycleOwner()
	if s == nil || s.manager == nil || s.manager.lifecycleOwner() != root || !safeTenantID(tenant) || !validSessionID(s.info.ID) {
		return errors.New("invalid session registration")
	}
	root.sessionMu.Lock()
	defer root.sessionMu.Unlock()
	if s.closed.Load() || s.ctx.Err() != nil {
		return ErrSessionClosed
	}
	if root.ownedSessions == nil {
		root.ownedSessions = make(map[string]registeredSession)
	}
	if _, found := root.ownedSessions[s.info.ID]; found {
		return errors.New("duplicate owned session ID")
	}
	root.ownedSessions[s.info.ID] = registeredSession{tenant: tenant, session: s}
	return nil
}

func (m *Manager) ownedSession(id, tenant string) (*Session, error) {
	if !validSessionID(id) || !safeTenantID(tenant) {
		return nil, ErrSessionClosed
	}
	root := m.lifecycleOwner()
	root.sessionMu.RLock()
	entry, ok := root.ownedSessions[id]
	root.sessionMu.RUnlock()
	if !ok || entry.tenant != tenant || entry.session.closed.Load() || entry.session.ctx.Err() != nil {
		return nil, ErrSessionClosed
	}
	return entry.session, nil
}

func (s *Session) unregisterOwnedSession() {
	if s.manager == nil {
		return
	}
	root := s.manager.lifecycleOwner()
	root.sessionMu.Lock()
	defer root.sessionMu.Unlock()
	if existing, found := root.ownedSessions[s.info.ID]; found && existing.session == s {
		delete(root.ownedSessions, s.info.ID)
	}
}
