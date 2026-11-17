package sandbox

// HTTP wire envelopes are named so the offline contract and the handlers use
// the same JSON fields. Internal launcher/guest commands retain their own types.
type StatusResponse struct {
	Status string `json:"status"`
}

type LegacyAPIErrorResponse struct {
	Error string `json:"error"`
}

// InferenceAPIErrorResponse retains an invocation ID after a possibly dispatched
// request. It is a specific extension of the common two-field API error.
type InferenceAPIErrorResponse struct {
	Code         string `json:"code"`
	Error        string `json:"error"`
	InvocationID string `json:"invocation_id,omitempty"`
}

type SessionTimeoutRequest struct {
	TTLMS int `json:"ttl_ms"`
}

type PreviewCreateRequest struct {
	TTLMS uint64 `json:"ttl_ms"`
}

type CodeContextCreateRequest struct {
	ID       string `json:"context_id"`
	Language string `json:"language"`
	Cwd      string `json:"cwd"`
}

type CodeContextDefaultRequest struct {
	Language string `json:"language"`
}

type CodeContextRestartRequest struct {
	Generation uint64 `json:"generation"`
}

type CodeExecutionRequest struct {
	ContextID   string            `json:"context_id"`
	Generation  uint64            `json:"generation"`
	ExecutionID string            `json:"execution_id"`
	Code        string            `json:"code"`
	Environment map[string]string `json:"environment"`
	TimeoutMS   *uint64           `json:"timeout_ms"`
}

type SessionCommandsResponse struct {
	SessionID string               `json:"session_id"`
	Commands  []SessionCommandInfo `json:"commands"`
}

type CommandCancelResponse struct {
	Killed bool `json:"killed"`
}

type SessionWatchesResponse struct {
	SessionID string             `json:"session_id"`
	Watches   []SessionWatchInfo `json:"watches"`
}

type WatchStopResponse struct {
	Stopped bool `json:"stopped"`
}

type CodeContextsResponse struct {
	SessionID string        `json:"session_id"`
	Contexts  []CodeContext `json:"contexts"`
}

type CodeExecutionAcceptedResponse struct {
	SessionID   string `json:"session_id"`
	ExecutionID string `json:"execution_id"`
	Accepted    bool   `json:"accepted"`
}

type CodeContextRemovedResponse struct {
	SessionID string `json:"session_id"`
	ContextID string `json:"context_id"`
	Removed   bool   `json:"removed"`
}

type PortConnectionResponse struct {
	SessionID  string          `json:"session_id"`
	Connection SessionPortInfo `json:"connection"`
}

type SessionOutputFrame struct {
	SessionID string `json:"session_id"`
	CommandID string `json:"command_id"`
	SessionOutputEvent
}

type SessionCommandTimeoutFrame struct {
	SessionID    string `json:"session_id"`
	CommandID    string `json:"command_id"`
	NextSequence int    `json:"next_sequence"`
}
