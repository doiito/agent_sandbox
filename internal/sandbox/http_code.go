package sandbox

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
)

func (a *API) sessionCode(w http.ResponseWriter, r *http.Request, command CodeCommand, status int) {
	session := a.lookupSession(r)
	if session == nil {
		writeJobError(w, 404, "not_found", "session not found", true)
		return
	}
	if !session.codeEnabled {
		writeSessionError(w, ErrCodeUnsupported)
		return
	}
	if err := command.Validate(); err != nil {
		writeSessionError(w, err)
		return
	}
	if command.Operation == "create" || command.Operation == "default" || command.Operation == "execute" || command.Operation == "restart" {
		language := command.Language
		if language == "" {
			var err error
			language, err = session.handle.codeLanguage(r.Context(), command.ContextID)
			if err != nil {
				writeSessionError(w, err)
				return
			}
		}
		if !session.tenant.allowsEntrypoint(codeEntrypoint(language)) {
			writeJobError(w, 403, "forbidden", "code interpreter is not allowed for tenant", true)
			return
		}
		if err := session.tenant.consumeRequestToken(); err != nil {
			writeJobError(w, 429, "busy", err.Error(), true)
			return
		}
	}
	response, err := session.handle.Code(r.Context(), command)
	if err != nil {
		writeSessionError(w, err)
		return
	}
	var value any
	switch response.Kind {
	case "context":
		value = response.Context
	case "contexts":
		value = CodeContextsResponse{SessionID: session.info.ID, Contexts: response.Contexts}
	case "execution":
		value = response.Execution
	case "accepted":
		value = CodeExecutionAcceptedResponse{SessionID: session.info.ID, ExecutionID: command.ExecutionID, Accepted: true}
	case "removed":
		value = CodeContextRemovedResponse{SessionID: session.info.ID, ContextID: command.ContextID, Removed: true}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}
func (a *API) createCodeContext(w http.ResponseWriter, r *http.Request) {
	var request CodeContextCreateRequest
	if err := decodeHTTPBody(w, r, &request); err != nil {
		writeJobError(w, 400, "invalid_json", err.Error(), true)
		return
	}
	if request.Cwd == "" {
		request.Cwd = "/workspace"
	}
	a.sessionCode(w, r, CodeCommand{Operation: "create", ContextID: request.ID, Language: request.Language, Cwd: request.Cwd}, 201)
}
func (a *API) defaultCodeContext(w http.ResponseWriter, r *http.Request) {
	var request CodeContextDefaultRequest
	if err := decodeHTTPBody(w, r, &request); err != nil {
		writeJobError(w, 400, "invalid_json", err.Error(), true)
		return
	}
	if request.Language == "" {
		request.Language = "python"
	}
	a.sessionCode(w, r, CodeCommand{Operation: "default", Language: request.Language}, 200)
}
func (a *API) listCodeContexts(w http.ResponseWriter, r *http.Request) {
	a.sessionCode(w, r, CodeCommand{Operation: "list"}, 200)
}
func (a *API) getCodeContext(w http.ResponseWriter, r *http.Request) {
	a.sessionCode(w, r, CodeCommand{Operation: "info", ContextID: r.PathValue("context")}, 200)
}
func (a *API) restartCodeContext(w http.ResponseWriter, r *http.Request) {
	var request CodeContextRestartRequest
	if err := decodeHTTPBody(w, r, &request); err != nil {
		writeJobError(w, 400, "invalid_json", err.Error(), true)
		return
	}
	a.sessionCode(w, r, CodeCommand{Operation: "restart", ContextID: r.PathValue("context"), Generation: request.Generation}, 202)
}
func codeGeneration(r *http.Request) (uint64, error) {
	value, err := strconv.ParseUint(r.URL.Query().Get("generation"), 10, 64)
	if err != nil || value == 0 {
		return 0, errors.New("generation is required")
	}
	return value, nil
}
func (a *API) removeCodeContext(w http.ResponseWriter, r *http.Request) {
	generation, err := codeGeneration(r)
	if err != nil {
		writeJobError(w, 400, "invalid_request", err.Error(), true)
		return
	}
	a.sessionCode(w, r, CodeCommand{Operation: "remove", ContextID: r.PathValue("context"), Generation: generation}, 202)
}
func (a *API) submitCodeExecution(w http.ResponseWriter, r *http.Request) {
	var request CodeExecutionRequest
	if err := decodeHTTPBody(w, r, &request); err != nil {
		writeJobError(w, 400, "invalid_json", err.Error(), true)
		return
	}
	timeout := uint64(60000)
	if request.TimeoutMS != nil {
		timeout = *request.TimeoutMS
	}
	a.sessionCode(w, r, CodeCommand{Operation: "execute", ContextID: request.ContextID, Generation: request.Generation, ExecutionID: request.ExecutionID, Code: request.Code, Environment: request.Environment, TimeoutMS: timeout}, 202)
}
func (a *API) getCodeExecution(w http.ResponseWriter, r *http.Request) {
	after := uint64(0)
	if text := r.URL.Query().Get("after"); text != "" {
		var err error
		after, err = strconv.ParseUint(text, 10, 64)
		if err != nil {
			writeJobError(w, 400, "invalid_request", "invalid code cursor", true)
			return
		}
	}
	a.sessionCode(w, r, CodeCommand{Operation: "execution", ExecutionID: r.PathValue("execution"), After: after}, 200)
}
func (a *API) cancelCodeExecution(w http.ResponseWriter, r *http.Request) {
	generation, err := codeGeneration(r)
	if err != nil {
		writeJobError(w, 400, "invalid_request", err.Error(), true)
		return
	}
	a.sessionCode(w, r, CodeCommand{Operation: "cancel", ContextID: r.URL.Query().Get("context_id"), Generation: generation, ExecutionID: r.PathValue("execution")}, 202)
}
func writeCodeError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, ErrCodeUnsupported) {
		writeJobError(w, 501, "code_unsupported", err.Error(), true)
		return true
	}
	var typed *CodeRequestError
	if !errors.As(err, &typed) {
		return false
	}
	status := 503
	switch typed.Code {
	case "unsupported":
		status = 501
	case "invalid_request", "invalid_binding":
		status = 400
	case "denied":
		status = 403
	case "not_found":
		status = 404
	case "conflict", "context_busy", "stale_context", "invalid_cursor":
		status = 409
	case "closed", "expired", "gone":
		status = 410
	case "quota", "busy":
		status = 429
	}
	code := typed.Code
	if code == "not_found" {
		// Keep an absent child distinct from an absent owning session. Clients
		// may confirm context removal only from the child-specific response.
		code = "code_not_found"
	}
	writeJobError(w, status, code, typed.Message, true)
	return true
}
