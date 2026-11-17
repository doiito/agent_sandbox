package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"
)

const inferenceRootProtocol = "osv-sandbox-inference-root/v1"
const inferenceGuestHost = "inference.osv.invalid"

type InferenceServiceConfig struct {
	LedgerDirectory string `json:"ledger_directory"`
	MaxTasks        int    `json:"max_tasks,omitempty"`
}

func validateInferenceServiceConfig(config *InferenceServiceConfig, production, guestProxy bool) error {
	if config == nil {
		return nil
	}
	if config.MaxTasks == 0 {
		config.MaxTasks = 4096
	}
	path := config.LedgerDirectory
	if !guestProxy || !filepath.IsAbs(path) || filepath.Clean(path) != path || config.MaxTasks < 1 || config.MaxTasks > 65536 {
		return errors.New("inference requires guest proxy, canonical ledger_directory and bounded max_tasks")
	}
	if production {
		for _, prefix := range []string{"/tmp", "/var/tmp", "/run", "/var/run", "/dev"} {
			if path == prefix || strings.HasPrefix(path, prefix+"/") {
				return errors.New("production inference ledger must use persistent storage")
			}
		}
		return validateInferencePersistentDirectory(path)
	}
	return nil
}

// Inspect the actual storage as well as its spelling. The final leaf may be
// created at startup beneath systemd's managed StateDirectory.
func validateInferencePersistentDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("inference storage path must be canonical and absolute")
	}
	found := false
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("production inference storage cannot contain symbolic links")
			}
			if !found {
				var fs syscall.Statfs_t
				if syscall.Statfs(current, &fs) != nil || uint64(fs.Type) == 0x1021994 || uint64(fs.Type) == 0x858458f6 {
					return errors.New("production inference storage cannot be an in-memory filesystem")
				}
				found = true
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return errors.New("cannot inspect production inference storage")
		}
		if current == "/" {
			break
		}
	}
	return nil
}

// NewConfiguredEgressServer attaches inference only when explicitly configured.
// Close must run after ServeEgress has joined its HTTP handlers.
func NewConfiguredEgressServer(auth *Authenticator, audit EgressAuditRecorder, config EgressServiceConfig) (*EgressServer, error) {
	if config.MaxConcurrent == 0 {
		config.MaxConcurrent = 16
	}
	if config.Inference != nil {
		copy := *config.Inference
		config.Inference = &copy
	}
	if err := validateInferenceServiceConfig(config.Inference, config.Production, config.GuestProxy); err != nil {
		return nil, err
	}
	server, err := NewEgressServer(auth, audit, config.CAFile, config.MaxConcurrent)
	if err != nil {
		return nil, err
	}
	server.GuestProxy = config.GuestProxy
	if config.Inference == nil {
		return server, nil
	}
	if err := os.Mkdir(config.Inference.LedgerDirectory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, errors.New("cannot create managed inference ledger")
	}
	ledger, err := OpenInferenceLedger(config.Inference.LedgerDirectory, config.Inference.MaxTasks)
	if err != nil {
		return nil, err
	}
	server.inference, err = newInferenceEngine(server, ledger)
	if err != nil {
		_ = ledger.Close()
		return nil, err
	}
	return server, nil
}

func (s *EgressServer) Close() error {
	if s.inference == nil {
		return nil
	}
	s.inference.Close()
	return s.inference.ledger.Close()
}

func inferenceControlSocketPath(main string) string {
	return filepath.Join(filepath.Dir(main), "inference.sock")
}

type inferenceRootRequest struct {
	PolicySHA256   string                  `json:"policy_sha256,omitempty"`
	Protocol       string                  `json:"protocol"`
	Binding        inferenceBinding        `json:"binding"`
	Invocation     *InferenceInvokeRequest `json:"invocation,omitempty"`
	ExportedSHA256 string                  `json:"exported_sha256,omitempty"`
}
type inferenceRootReply struct {
	Protocol string          `json:"protocol"`
	Bill     *InferenceBill  `json:"bill,omitempty"`
	Record   json.RawMessage `json:"record,omitempty"`
	SHA256   string          `json:"sha256,omitempty"`
	Retired  bool            `json:"retired,omitempty"`
}

func marshalInferenceJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(value)
	return buffer.Bytes(), err
}
func writeInferenceJSON(w http.ResponseWriter, status int, value any) {
	data, err := marshalInferenceJSON(value)
	if err != nil {
		writeJobError(w, 503, "inference_protocol", "inference response unavailable", true)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}
func writeInferenceError(w http.ResponseWriter, err error, id string) {
	failure := inferenceFailure(err, id)
	writeInferenceJSON(w, failure.Status, map[string]any{"protocol": "osv-sandbox-inference-error/v1", "error": failure})
}

func readInferenceRequest(r *http.Request, limit int, target any) error {
	if r.Header.Get("Content-Encoding") != "" || r.ContentLength > int64(limit) {
		return inferenceError(400, "inference_request")
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if err != nil || len(data) > limit || !utf8.Valid(data) || decodeInferenceJSON(data, target) != nil {
		return inferenceError(400, "inference_request")
	}
	return nil
}

func (s *EgressServer) serveInferenceRoot(w http.ResponseWriter, r *http.Request, control bool) {
	uid, known := r.Context().Value(egressPeerKey{}).(uint32)
	if !known || uid != 0 || s.inference == nil || !s.GuestProxy {
		writeInferenceError(w, inferenceError(403, "inference_root_required"), "")
		return
	}
	operation := strings.TrimPrefix(r.URL.Path, "/v1/inference/root/")
	if r.Method != "POST" || r.URL.RawQuery != "" || operation == r.URL.Path {
		writeInferenceError(w, inferenceError(404, "inference_not_found"), "")
		return
	}
	if (operation == "invoke") == control {
		writeInferenceError(w, inferenceError(403, "inference_control_channel"), "")
		return
	}
	limit := 8192
	if operation == "invoke" {
		limit += egressRequestLimit
	}
	var request inferenceRootRequest
	if err := readInferenceRequest(r, limit, &request); err != nil {
		writeInferenceError(w, err, "")
		return
	}
	bindingValid := request.Binding.valid()
	if operation == "inspect" {
		bindingValid = safeTenantID(request.Binding.Tenant) && canonicalJobID(request.Binding.TaskID) && request.Binding.VMID == "" && request.Binding.LeaseID == ""
	}
	if request.Protocol != inferenceRootProtocol || !bindingValid ||
		(operation == "invoke") != (request.Invocation != nil) || (operation == "retire") != (request.ExportedSHA256 != "") ||
		request.PolicySHA256 != "" && (operation != "invoke" || !validSHA256Hex(request.PolicySHA256)) {
		writeInferenceError(w, inferenceError(400, "inference_request"), "")
		return
	}
	e := s.inference
	if operation == "invoke" {
		if request.PolicySHA256 != "" && inferenceTenantPolicyDigest(e.tenants[request.Binding.Tenant]) != request.PolicySHA256 {
			writeInferenceError(w, inferenceError(503, "inference_policy_unavailable"), request.Invocation.ID)
			return
		}
		if _, err := e.ledger.boundTask(request.Binding, true); err != nil {
			writeInferenceError(w, e.lifecycleFailure(err), request.Invocation.ID)
			return
		}
		result, err := e.invoke(r.Context(), request.Binding, *request.Invocation)
		if err != nil {
			writeInferenceError(w, err, request.Invocation.ID)
		} else {
			writeInferenceJSON(w, 200, result)
		}
		return
	}
	var bill InferenceBill
	var err error
	reply := inferenceRootReply{Protocol: inferenceRootProtocol}
	switch operation {
	case "inspect":
		_, complete, startErr := e.begin(r.Context())
		if startErr != nil {
			err = startErr
			break
		}
		defer complete()
		bill, err = e.ledger.bill(request.Binding.Tenant, request.Binding.TaskID)
		if err != nil {
			err = e.lifecycleFailure(err)
		}
		reply.Bill = &bill
	case "bind":
		bill, err = e.bindTask(r.Context(), request.Binding)
		reply.Bill = &bill
	case "close":
		bill, err = e.closeTask(r.Context(), request.Binding)
		reply.Bill = &bill
	case "export", "retire":
		_, complete, startErr := e.begin(r.Context())
		if startErr != nil {
			err = startErr
			break
		}
		defer complete()
		if operation == "export" {
			reply.Record, reply.SHA256, err = e.ledger.exportTask(request.Binding)
		} else if !validSHA256Hex(request.ExportedSHA256) {
			err = inferenceError(400, "inference_export_digest")
		} else if err = e.lifecycleAudit("infer.retire_intent", request.Binding); err == nil {
			err = e.ledger.retireTask(request.Binding, request.ExportedSHA256)
			reply.Retired = err == nil
		}
		if err == nil {
			err = e.lifecycleAudit("infer."+operation, request.Binding)
		} else {
			err = e.lifecycleFailure(err)
		}
	default:
		err = inferenceError(404, "inference_not_found")
	}
	if err != nil {
		writeInferenceError(w, err, "")
		return
	}
	writeInferenceJSON(w, 200, reply)
}

func (s *EgressServer) serveInferenceQuery(w http.ResponseWriter, r *http.Request, tenant *tenantRuntime) {
	if s.inference == nil {
		writeInferenceError(w, inferenceError(403, "inference_disabled"), "")
		return
	}
	if r.Method != "GET" || r.URL.RawQuery != "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		writeInferenceError(w, inferenceError(400, "inference_request"), "")
		return
	}
	if r.URL.Path == "/v1/inference/state" {
		state := inferenceServiceState{Protocol: "osv-sandbox-inference-state/v1", Billing: s.inference.ledger.Err() == nil}
		if state.Billing && tenant.inference != nil && s.inference.health() == nil {
			policy := tenant.inference.capabilities()
			state.Policy, state.PolicySHA256 = &policy, inferenceTenantPolicyDigest(tenant)
		}
		writeInferenceJSON(w, 200, state)
		return
	}
	if tenant.consumeRequestToken() != nil {
		writeInferenceError(w, inferenceError(429, "inference_rate_limit"), "")
		return
	}
	if r.URL.Path == "/v1/inference/policy" {
		if tenant.inference == nil {
			writeInferenceError(w, inferenceError(403, "inference_disabled"), "")
			return
		}
		if err := s.inference.health(); err != nil {
			writeInferenceError(w, err, "")
			return
		}
		writeInferenceJSON(w, 200, tenant.inference.capabilities())
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/inference/bills/")
	if id == r.URL.Path || !canonicalJobID(id) {
		writeInferenceError(w, inferenceError(404, "inference_not_found"), "")
		return
	}
	// History remains readable if current egress permission is revoked. These
	// reads never acquire a model slot or expose model inputs/outputs.
	bill, err := s.inference.ledger.bill(tenant.policy.ID, id)
	if err != nil {
		writeInferenceError(w, s.inference.lifecycleFailure(err), "")
		return
	}
	writeInferenceJSON(w, 200, bill)
}
