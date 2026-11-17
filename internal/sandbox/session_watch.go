package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

type watchRecord struct {
	mu           sync.Mutex
	info         SessionWatchInfo
	events       []SessionWatchEvent
	bytes        int
	acknowledged int
	last         int
	cancel       context.CancelFunc
	done         chan struct{}
	once         sync.Once
}

func (r *watchRecord) finish(state, code string) {
	r.once.Do(func() {
		r.cancel()
		r.mu.Lock()
		r.info.State, r.info.ErrorCode = state, code
		r.mu.Unlock()
		close(r.done)
	})
}

func (s *Session) StartFileWatch(ctx context.Context, request SessionWatchRequest) (SessionWatchInfo, error) {
	if s.manager == nil || !s.manager.hasLinuxWatchFeature() || !s.backend.FileWatch {
		return SessionWatchInfo{}, ErrWatchUnsupported
	}
	if err := request.Validate(); err != nil {
		return SessionWatchInfo{}, err
	}
	if s.closed.Load() || s.ctx.Err() != nil {
		return SessionWatchInfo{}, ErrSessionClosed
	}
	if ctx.Err() != nil {
		return SessionWatchInfo{}, ctx.Err()
	}
	s.lifecycleMu.Lock()
	remaining := time.Until(s.hardDeadline)
	s.lifecycleMu.Unlock()
	if request.TimeoutMS > 0 && time.Duration(request.TimeoutMS)*time.Millisecond > remaining {
		return SessionWatchInfo{}, ErrTimeoutBeyondLifetime
	}
	id, err := randomID()
	if err != nil {
		return SessionWatchInfo{}, err
	}
	identity, err := newLinuxGuestBinding(s.info.ID)
	if err != nil {
		return SessionWatchInfo{}, err
	}
	lifetime, cancel := context.WithCancel(s.ctx)
	if request.TimeoutMS > 0 {
		baseCancel := cancel
		bounded, stop := context.WithTimeout(lifetime, time.Duration(request.TimeoutMS)*time.Millisecond)
		lifetime = bounded
		cancel = func() { stop(); baseCancel() }
	}
	record := &watchRecord{info: SessionWatchInfo{ID: id, SessionID: s.info.ID, Path: request.Path, Recursive: request.Recursive, IncludeEntry: request.IncludeEntry, State: "starting", CreatedAt: time.Now().UTC()}, cancel: cancel, done: make(chan struct{})}
	s.watchesMu.Lock()
	if s.closed.Load() || s.ctx.Err() != nil {
		s.watchesMu.Unlock()
		cancel()
		return SessionWatchInfo{}, ErrSessionClosed
	}
	active := 0
	for _, r := range s.watches {
		r.mu.Lock()
		if r.info.State == "watching" || r.info.State == "starting" {
			active++
		}
		r.mu.Unlock()
	}
	if active >= sessionWatchActiveLimit {
		s.watchesMu.Unlock()
		cancel()
		return SessionWatchInfo{}, ErrBusy
	}
	if s.watches == nil {
		s.watches = make(map[string]*watchRecord)
	}
	for len(s.watchOrder) >= sessionWatchHistoryLimit {
		removed := false
		for n, key := range s.watchOrder {
			r := s.watches[key]
			r.mu.Lock()
			finished := r.info.State != "starting" && r.info.State != "watching"
			r.mu.Unlock()
			if finished {
				delete(s.watches, key)
				s.watchOrder = append(s.watchOrder[:n], s.watchOrder[n+1:]...)
				removed = true
				break
			}
		}
		if !removed {
			s.watchesMu.Unlock()
			cancel()
			return SessionWatchInfo{}, ErrBusy
		}
	}
	s.watches[id] = record
	s.watchOrder = append(s.watchOrder, id)
	s.watchesMu.Unlock()
	wire := linuxWatchRequest{SessionID: s.info.ID, WatchID: id, Nonce: identity.Nonce, Path: request.Path, Recursive: request.Recursive, IncludeEntry: request.IncludeEntry, TimeoutMS: request.TimeoutMS, Binding: s.binding}
	stream, err := s.backend.openFileWatch(ctx, lifetime, wire, s.workdir)
	if err != nil || ctx.Err() != nil || lifetime.Err() != nil || s.closed.Load() {
		if stream != nil {
			stream.Close()
		}
		record.finish("closed", "")
		s.watchesMu.Lock()
		delete(s.watches, id)
		for n, key := range s.watchOrder {
			if key == id {
				s.watchOrder = append(s.watchOrder[:n], s.watchOrder[n+1:]...)
				break
			}
		}
		s.watchesMu.Unlock()
		if err == nil {
			err = ErrSessionClosed
		}
		if errors.Is(err, errWatchProtocol) {
			_ = s.Close()
			err = ErrUnavailable
		}
		return SessionWatchInfo{}, err
	}
	record.mu.Lock()
	record.info.State = "watching"
	info := record.info
	record.mu.Unlock()
	go s.receiveFileWatch(lifetime, record, stream)
	return info, nil
}

func (s *Session) receiveFileWatch(ctx context.Context, r *watchRecord, stream *linuxWatchStream) {
	state, code := "closed", ""
	defer func() {
		stream.Close()
		r.finish(state, code)
		if code == "protocol_error" {
			_ = s.Close()
		}
	}()
	for {
		event, end, err := stream.Next()
		if err != nil {
			if ctx.Err() != nil {
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					code = "expired"
				}
				return
			}
			state, code = "failed", "transport_error"
			if errors.Is(err, errWatchProtocol) {
				code = "protocol_error"
			}
			return
		}
		if end != "" {
			if end == "invalid_binding" {
				state, code = "failed", "protocol_error"
				return
			}
			code = end
			if end != "expired" && end != "closed" {
				state = "failed"
			}
			return
		}
		encoded, err := json.Marshal(event)
		if err != nil {
			state, code = "failed", "protocol_error"
			return
		}
		if len(encoded) > sessionWatchFrameLimit && event.Entry != nil {
			event.Entry = nil
			encoded, _ = json.Marshal(event)
		}
		r.mu.Lock()
		if len(r.events) >= sessionWatchEventLimit || r.bytes+len(encoded) > sessionWatchByteLimit {
			r.mu.Unlock()
			state, code = "failed", "overflow"
			return
		}
		r.events = append(r.events, *event)
		r.bytes += len(encoded)
		r.last = event.Sequence
		r.mu.Unlock()
	}
}

func (s *Session) fileWatch(id string) (*watchRecord, error) {
	if !validSessionID(id) {
		return nil, ErrWatchNotFound
	}
	s.watchesMu.Lock()
	r := s.watches[id]
	s.watchesMu.Unlock()
	if r == nil {
		return nil, ErrWatchNotFound
	}
	return r, nil
}

func copyWatchEvent(source SessionWatchEvent) SessionWatchEvent {
	if source.Entry == nil {
		return source
	}
	info := *source.Entry
	if info.SymlinkTarget != nil {
		target := *info.SymlinkTarget
		info.SymlinkTarget = &target
	}
	if info.Metadata != nil {
		info.Metadata = make(map[string]string, len(source.Entry.Metadata))
		for k, v := range source.Entry.Metadata {
			info.Metadata[k] = v
		}
	}
	source.Entry = &info
	return source
}

func (s *Session) PollFileWatch(id string, after int) (SessionWatchPage, error) {
	r, err := s.fileWatch(id)
	if err != nil {
		return SessionWatchPage{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if after < r.acknowledged || after > r.last {
		return SessionWatchPage{}, ErrWatchCursor
	}
	if after > r.acknowledged {
		count := after - r.acknowledged
		if count > len(r.events) {
			return SessionWatchPage{}, ErrWatchCursor
		}
		for _, event := range r.events[:count] {
			data, _ := json.Marshal(event)
			r.bytes -= len(data)
		}
		for n := 0; n < count; n++ {
			r.events[n] = SessionWatchEvent{}
		}
		r.events = append([]SessionWatchEvent{}, r.events[count:]...)
		r.acknowledged = after
	}
	count := min(len(r.events), sessionWatchPageLimit)
	events := make([]SessionWatchEvent, count)
	for n := range events {
		events[n] = copyWatchEvent(r.events[n])
	}
	next := after + count
	return SessionWatchPage{Info: r.info, Events: events, NextSequence: next, Complete: r.info.State != "watching" && r.info.State != "starting" && next == r.last}, nil
}

func (s *Session) StopFileWatch(id string) (bool, error) {
	r, err := s.fileWatch(id)
	if err != nil {
		return false, err
	}
	r.mu.Lock()
	active := r.info.State == "watching" || r.info.State == "starting"
	r.mu.Unlock()
	r.cancel()
	select {
	case <-r.done:
		return active, nil
	case <-time.After(2 * time.Second):
		return false, fmt.Errorf("%w: directory watch cleanup timed out", ErrUnavailable)
	}
}

func (s *Session) ListFileWatches() []SessionWatchInfo {
	s.watchesMu.Lock()
	defer s.watchesMu.Unlock()
	infos := make([]SessionWatchInfo, 0, len(s.watchOrder))
	for _, id := range s.watchOrder {
		r := s.watches[id]
		r.mu.Lock()
		infos = append(infos, r.info)
		r.mu.Unlock()
	}
	return infos
}

func (s *Session) closeFileWatches() error {
	s.watchesMu.Lock()
	records := make([]*watchRecord, 0, len(s.watches))
	for _, r := range s.watches {
		records = append(records, r)
	}
	s.watchesMu.Unlock()
	for _, r := range records {
		r.cancel()
	}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for _, r := range records {
		select {
		case <-r.done:
		case <-deadline.C:
			return errors.New("directory watch cleanup timed out")
		}
	}
	return nil
}
