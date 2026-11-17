package sandbox

import (
	"context"
	"errors"
	"slices"
	"time"
)

type codeExecutionBinding struct {
	ContextID  string
	Generation uint64
	Language   string
}

func codeEntrypoint(language string) string {
	if language == "python" {
		return "/opt/python/bin/python3.12"
	}
	return "/opt/node/bin/node"
}
func (s *Session) codeLanguage(ctx context.Context, id string) (string, error) {
	s.codeMu.Lock()
	language := s.codeContexts[id]
	s.codeMu.Unlock()
	if language != "" {
		return language, nil
	}
	response, err := s.Code(ctx, CodeCommand{Operation: "info", ContextID: id})
	if err != nil {
		return "", err
	}
	return response.Context.Language, nil
}

// Code is independent of the main command connection and its opMu. The
// original owning session still holds the VM and every capacity reservation.
func (s *Session) Code(ctx context.Context, request CodeCommand) (CodeResponse, error) {
	if s.manager == nil || !s.manager.hasLinuxCodeFeature() || !s.backend.CodeContexts {
		return CodeResponse{}, ErrCodeUnsupported
	}
	if err := request.Validate(); err != nil {
		return CodeResponse{}, err
	}
	if ctx.Err() != nil {
		return CodeResponse{}, ctx.Err()
	}
	if s.closed.Load() || s.ctx.Err() != nil {
		return CodeResponse{}, ErrSessionClosed
	}
	s.lifecycleMu.Lock()
	lease := s.leaseDeadline
	hard := s.hardDeadline
	s.lifecycleMu.Unlock()
	if !lease.IsZero() && !time.Now().Before(lease) || !hard.IsZero() && !time.Now().Before(hard) {
		return CodeResponse{}, ErrSessionClosed
	}
	if !lease.IsZero() {
		bounded, cancel := context.WithDeadline(ctx, lease)
		defer cancel()
		ctx = bounded
	}
	var binding codeExecutionBinding
	if request.Operation == "create" || request.Operation == "default" || request.Operation == "execute" || request.Operation == "restart" {
		language := request.Language
		if language == "" {
			var err error
			language, err = s.codeLanguage(ctx, request.ContextID)
			if err != nil {
				return CodeResponse{}, err
			}
		}
		if !slices.Contains(s.manager.config.AllowedEntrypoints, codeEntrypoint(language)) {
			return CodeResponse{}, &CodeRequestError{Code: "denied", Message: "code interpreter is not allowed by template policy"}
		}
	}
	if request.Operation == "execute" || request.Operation == "cancel" {
		language, err := s.codeLanguage(ctx, request.ContextID)
		if err != nil {
			return CodeResponse{}, err
		}
		binding = codeExecutionBinding{request.ContextID, request.Generation, language}
		s.codeMu.Lock()
		if s.codeExecutions == nil {
			s.codeExecutions = map[string]codeExecutionBinding{}
		}
		previous, exists := s.codeExecutions[request.ExecutionID]
		if exists && (previous != binding || request.Operation == "execute") {
			s.codeMu.Unlock()
			return CodeResponse{}, &CodeRequestError{Code: "conflict", Message: "execution ID already reserved; query its journal"}
		}
		if !exists && len(s.codeExecutions) >= 256 {
			s.codeMu.Unlock()
			return CodeResponse{}, &CodeRequestError{Code: "quota", Message: "execution identity quota exceeded"}
		}
		s.codeExecutions[request.ExecutionID] = binding
		s.codeMu.Unlock()
	}
	if request.Operation == "execution" {
		s.codeMu.Lock()
		var exists bool
		binding, exists = s.codeExecutions[request.ExecutionID]
		s.codeMu.Unlock()
		if !exists {
			return CodeResponse{}, &CodeRequestError{Code: "not_found", Message: "execution not found"}
		}
	}
	identity, err := newLinuxGuestBinding(s.info.ID)
	if err != nil {
		return CodeResponse{}, err
	}
	response, err := s.backend.exchangeCode(ctx, s.ctx, linuxCodeRequest{SessionID: s.info.ID, Nonce: identity.Nonce, Binding: s.binding, Request: request}, s.workdir)
	if errors.Is(err, errCodeProtocol) {
		_ = s.Close()
		return CodeResponse{}, ErrUnavailable
	}
	// Reserve identities even when delivery is uncertain. Explicit cancellation
	// can precede submission, and must prevent a late retry from admitting code.
	if err != nil {
		return CodeResponse{}, err
	}
	if response.Execution != nil {
		if response.Execution.ContextID != binding.ContextID || response.Execution.Generation != binding.Generation {
			_ = s.Close()
			return CodeResponse{}, ErrUnavailable
		}
		response.Execution.Language = binding.Language
	}
	s.codeMu.Lock()
	if s.codeContexts == nil {
		s.codeContexts = map[string]string{}
	}
	contexts := response.Contexts
	if response.Context != nil {
		contexts = append(contexts, *response.Context)
	}
	for _, context := range contexts {
		if previous := s.codeContexts[context.ID]; previous != "" && previous != context.Language || len(s.codeContexts) >= 256 && s.codeContexts[context.ID] == "" {
			s.codeMu.Unlock()
			_ = s.Close()
			return CodeResponse{}, ErrUnavailable
		}
		s.codeContexts[context.ID] = context.Language
	}
	s.codeMu.Unlock()
	response.bindSession(s.info.ID)
	return response, nil
}
