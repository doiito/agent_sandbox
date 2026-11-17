package sandbox

import (
	"errors"
	"time"
)

const sessionMaxLifetimeMS = 600_000

func sessionLifetimeMS(config Config) int {
	if config.SessionMaxLifetimeMS > 0 {
		return config.SessionMaxLifetimeMS
	}
	return sessionMaxLifetimeMS
}

var ErrTimeoutBeyondLifetime = errors.New("timeout exceeds the remaining VM lifetime")

func (s *Session) startLeaseWatch(soft, hard time.Time) {
	s.lifecycleMu.Lock()
	s.leaseDeadline = soft
	s.hardDeadline = hard
	s.info.ExpiresAt = soft.UTC()
	s.info.LeaseRevision = 1
	s.info.MaxExpiresAt = hard.UTC()
	s.leaseTimer = time.NewTimer(time.Until(soft))
	timer := s.leaseTimer
	s.lifecycleMu.Unlock()
	go func() {
		for {
			select {
			case <-s.ctx.Done():
				_ = s.Close()
				return
			case <-s.instance.ctx.Done():
				_ = s.Close()
				return
			case <-timer.C:
				s.lifecycleMu.Lock()
				expired := !time.Now().Before(s.leaseDeadline)
				if expired {
					s.closed.Store(true)
				}
				s.lifecycleMu.Unlock()
				if expired {
					s.cancel()
					_ = s.Close()
					return
				}
			}
		}
	}()
}
func (s *Session) SetTimeout(ttlMS int) (SessionInfo, error) {
	if ttlMS < sessionMinTTLMS || ttlMS > sessionMaxTTLMS {
		return SessionInfo{}, errors.New("ttl_ms must be in [1000,300000]")
	}
	s.lifecycleMu.Lock()
	now := time.Now()
	if s.closed.Load() || s.ctx.Err() != nil || s.instance.ctx.Err() != nil || !now.Before(s.leaseDeadline) {
		s.lifecycleMu.Unlock()
		return SessionInfo{}, ErrSessionClosed
	}
	deadline := now.Add(time.Duration(ttlMS) * time.Millisecond)
	if s.hardDeadline.IsZero() || deadline.After(s.hardDeadline) {
		s.lifecycleMu.Unlock()
		return SessionInfo{}, ErrTimeoutBeyondLifetime
	}
	s.leaseDeadline = deadline
	s.info.ExpiresAt = deadline.UTC()
	s.info.LeaseRevision++
	s.leaseTimer.Reset(time.Until(deadline))
	info := s.infoSnapshotLocked()
	s.lifecycleMu.Unlock()
	return info, nil
}
func (s *Session) infoSnapshotLocked() SessionInfo {
	info := s.info
	info.StartupTiming = info.StartupTiming.clone()
	if !s.leaseDeadline.IsZero() {
		info.RemainingTTLMS = max(0, time.Until(s.leaseDeadline).Milliseconds())
	}
	return info
}
