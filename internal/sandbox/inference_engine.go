package sandbox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"
)

type inferenceCredentialKey struct{ tenant, endpoint string }
type inferenceActiveCall struct {
	cancel  context.CancelFunc
	binding *inferenceBinding
	done    chan struct{}
}

// Callers obtain the binding from the trusted launcher, never a guest header.
// Public API/guest/signature integration has its own acceptance gate.
type inferenceEngine struct {
	egress      *EgressServer
	ledger      *InferenceLedger
	tenants     map[string]*tenantRuntime
	credentials map[inferenceCredentialKey]string
	mu          sync.Mutex
	closing     bool
	failed      bool
	active      map[*inferenceActiveCall]struct{}
	draining    map[string]*inferenceDrain
	wg          sync.WaitGroup
}

func newInferenceEngine(server *EgressServer, ledger *InferenceLedger) (*inferenceEngine, error) {
	if server == nil || server.auth == nil || server.audit == nil || server.engine == nil || ledger == nil || ledger.Err() != nil {
		return nil, errors.New("invalid inference engine dependencies")
	}
	e := &inferenceEngine{egress: server, ledger: ledger, tenants: map[string]*tenantRuntime{},
		credentials: map[inferenceCredentialKey]string{}, active: map[*inferenceActiveCall]struct{}{}, draining: map[string]*inferenceDrain{}}
	for _, tenant := range server.auth.tenants {
		e.tenants[tenant.policy.ID] = tenant
		if tenant.inference == nil {
			continue
		}
		for _, endpoint := range tenant.inference.policy.Endpoints {
			if endpoint.Credential != nil {
				value, err := readInferenceCredential(*endpoint.Credential)
				if err != nil {
					return nil, errors.New("cannot load private inference credential")
				}
				e.credentials[inferenceCredentialKey{tenant.policy.ID, endpoint.Name}] = value
			}
		}
	}
	return e, nil
}

// Credential values are cached only in the egress process. Rotation takes
// effect at its next restart. Pin the parent directory before opening the file.
func readInferenceCredential(credential InferenceCredential) (string, error) {
	failure := errors.New("invalid private inference credential")
	parent, err := os.OpenFile(filepath.Dir(credential.File), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", failure
	}
	defer parent.Close()
	info, err := parent.Stat()
	if err != nil || !info.IsDir() || !inferenceOwned(info) || info.Mode().Perm()&0o022 != 0 {
		return "", failure
	}
	path := "/proc/self/fd/" + strconv.FormatUint(uint64(parent.Fd()), 10) + "/" + filepath.Base(credential.File)
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", failure
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !inferencePrivateFile(info) || info.Size() > 4098 {
		return "", failure
	}
	data, err := io.ReadAll(io.LimitReader(file, 4099))
	if err != nil || len(data) > 4098 {
		return "", failure
	}
	secret := string(data)
	if strings.HasSuffix(secret, "\n") {
		secret = strings.TrimSuffix(strings.TrimSuffix(secret, "\n"), "\r")
	}
	if secret == "" || len(credential.Prefix)+len(secret) > 4096 {
		return "", failure
	}
	for _, character := range secret {
		if character < 32 || character > 126 {
			return "", failure
		}
	}
	return credential.Prefix + secret, nil
}

func (e *inferenceEngine) fail() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.failed = true
	for call := range e.active {
		call.cancel()
	}
}

func (e *inferenceEngine) health() error {
	e.mu.Lock()
	unavailable := e.closing || e.failed
	e.mu.Unlock()
	if unavailable {
		return inferenceError(503, "inference_unavailable")
	}
	if e.egress.audit.Err() != nil {
		e.fail()
		return inferenceError(503, "inference_audit")
	}
	if e.ledger.Err() != nil {
		e.fail()
		return inferenceError(503, "inference_store")
	}
	return nil
}

func (e *inferenceEngine) appendAudit(event EgressAuditEvent) error {
	if e.egress.audit.AppendNetwork(event) != nil {
		e.fail()
		return inferenceError(503, "inference_audit")
	}
	return nil
}

func (e *inferenceEngine) begin(parent context.Context) (context.Context, func(), error) {
	return e.beginCall(parent, nil)
}

func (e *inferenceEngine) beginCall(parent context.Context, binding *inferenceBinding) (context.Context, func(), error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closing || e.failed {
		return nil, nil, inferenceError(503, "inference_unavailable")
	}
	if binding != nil && e.draining[binding.TaskID] != nil {
		return nil, nil, inferenceError(409, "inference_task_closed")
	}
	ctx, cancel := context.WithCancel(parent)
	call := &inferenceActiveCall{cancel: cancel, done: make(chan struct{})}
	if binding != nil {
		copy := *binding
		call.binding = &copy
	}
	e.active[call] = struct{}{}
	e.wg.Add(1)
	return ctx, func() {
		cancel()
		e.mu.Lock()
		delete(e.active, call)
		close(call.done)
		e.mu.Unlock()
		e.wg.Done()
	}, nil
}

// Close cancels and joins all invocations, including their final bill/audit
// writes. The service owns the ledger and may close it only after this returns.
func (e *inferenceEngine) Close() {
	e.mu.Lock()
	e.closing = true
	for call := range e.active {
		call.cancel()
	}
	e.mu.Unlock()
	e.wg.Wait()
}

func (e *inferenceEngine) tenant(binding inferenceBinding) (*tenantRuntime, error) {
	tenant := e.tenants[binding.Tenant]
	if !binding.valid() || tenant == nil || tenant.egress == nil || tenant.inference == nil {
		return nil, inferenceError(403, "inference_disabled")
	}
	return tenant, nil
}

func inferenceFailure(err error, id string) *InferenceError {
	var failure *InferenceError
	if !errors.As(err, &failure) {
		failure = &InferenceError{Status: 503, Code: "inference_store"}
	}
	copy := *failure
	if canonicalJobID(id) {
		copy.InvocationID = id
	}
	return &copy
}

func inferenceAudit(binding inferenceBinding, request InferenceInvokeRequest) EgressAuditEvent {
	event := EgressAuditEvent{Tenant: binding.Tenant, TaskID: binding.TaskID, VMID: binding.VMID, LeaseID: binding.LeaseID, Method: "POST"}
	if canonicalJobID(request.ID) {
		event.RequestID = request.ID
	}
	if inferenceEndpointName.MatchString(request.Endpoint) {
		event.Endpoint = request.Endpoint
	}
	return event
}

func (e *inferenceEngine) deny(binding inferenceBinding, request InferenceInvokeRequest, err error) (InferenceInvokeResult, error) {
	failure := inferenceFailure(err, request.ID)
	event := inferenceAudit(binding, request)
	event.Event, event.Code = "infer.deny", failure.Code
	if auditErr := e.appendAudit(event); auditErr != nil {
		failure = inferenceFailure(auditErr, request.ID)
	}
	return InferenceInvokeResult{}, failure
}

// invoke shares the existing tenant/global rate and work quotas.
func (e *inferenceEngine) invoke(ctx context.Context, binding inferenceBinding, request InferenceInvokeRequest) (InferenceInvokeResult, error) {
	return e.invokeWithAdmission(ctx, binding, request, true)
}

// The trusted guest upgrade already paid rate admission and holds a bounded
// transport slot. It must still acquire the same model work capacity.
func (e *inferenceEngine) invokeFromGuest(ctx context.Context, binding inferenceBinding, request InferenceInvokeRequest) (InferenceInvokeResult, error) {
	return e.invokeWithAdmission(ctx, binding, request, false)
}

func (e *inferenceEngine) invokeWithAdmission(ctx context.Context, binding inferenceBinding, request InferenceInvokeRequest, consumeRate bool) (InferenceInvokeResult, error) {
	ctx, complete, err := e.beginCall(ctx, &binding)
	if err != nil {
		return InferenceInvokeResult{}, inferenceFailure(err, request.ID)
	}
	defer complete()
	tenant, err := e.tenant(binding)
	if err != nil {
		return InferenceInvokeResult{}, inferenceFailure(err, request.ID)
	}
	if err := e.health(); err != nil {
		return InferenceInvokeResult{}, inferenceFailure(err, request.ID)
	}
	var release func()
	if consumeRate {
		release, err = e.egress.acquireProxySlot(tenant)
	} else {
		release, err = e.egress.acquireProxyCapacity(tenant)
	}
	if err != nil {
		code := "inference_busy"
		var failure *EgressError
		if errors.As(err, &failure) && failure.Code == "egress_rate_limit" {
			code = "inference_rate_limit"
		}
		return e.deny(binding, request, inferenceError(429, code))
	}
	defer release()
	return e.invokeCore(ctx, binding, request)
}

func (e *inferenceEngine) invokeCore(ctx context.Context, binding inferenceBinding, request InferenceInvokeRequest) (InferenceInvokeResult, error) {
	tenant, err := e.tenant(binding)
	if err != nil {
		return InferenceInvokeResult{}, inferenceFailure(err, request.ID)
	}
	if err := e.health(); err != nil {
		return InferenceInvokeResult{}, inferenceFailure(err, request.ID)
	}
	rules := tenant.inference
	if !canonicalJobID(request.ID) || request.TimeoutMS < 0 || request.TimeoutMS > rules.timeoutMS ||
		len(request.Payload) < 1 || len(request.Payload) > rules.request || !utf8.Valid(request.Payload) || !json.Valid(request.Payload) {
		return e.deny(binding, request, inferenceError(400, "inference_request"))
	}
	permit, err := rules.permit(request.Endpoint)
	if err != nil {
		return e.deny(binding, request, inferenceError(403, "inference_endpoint"))
	}
	started := time.Now()
	reservation, err := e.ledger.reserve(binding, request.ID, permit, uint64(len(request.Payload)))
	if err != nil {
		if e.ledger.Err() != nil {
			e.fail()
		}
		return e.deny(binding, request, err)
	}
	endpoint := rules.endpoints[request.Endpoint]
	_, origin, _ := egressURL(endpoint.URL) // Immutable endpoint was compiled with the egress policy.
	event := inferenceAudit(binding, request)
	event.Event, event.Origin = "infer.admit", origin
	event.Inference = &InferenceAuditMeter{State: "reserved", ReservedUnits: reservation.ReservedUnits, HeldUnits: reservation.ReservedUnits}
	admitErr := e.appendAudit(event)
	result := NetworkFetchResult{}
	observation := &egressFetchObservation{}
	var auditFailed atomic.Bool
	var fetchErr error
	if admitErr == nil {
		headers := map[string]string{"Content-Type": "application/json", "Accept": "application/json"}
		if endpoint.Credential != nil {
			headers[endpoint.Credential.Header] = e.credentials[inferenceCredentialKey{binding.Tenant, endpoint.Name}]
		}
		result, fetchErr = e.egress.engine.fetchObserved(ctx, NetworkFetchRequest{URL: endpoint.URL, Method: "POST", Headers: headers,
			BodyBase64: base64.StdEncoding.EncodeToString(request.Payload), TimeoutMS: request.TimeoutMS}, tenant.egress,
			func(origin, method, ip string, hop int) error {
				if err := e.health(); err != nil {
					return egressError(503, "egress_audit")
				}
				allowed := inferenceAudit(binding, request)
				allowed.Event, allowed.Origin, allowed.Method, allowed.IP, allowed.Hop = "infer.allow", origin, method, ip, hop
				if e.appendAudit(allowed) != nil {
					auditFailed.Store(true)
					return egressError(503, "egress_audit")
				}
				return nil
			}, observation)
	}
	outcome := inferenceOutcome{state: "failed", status: result.Status, outputBytes: uint64(result.ResponseBytes),
		dispatched: observation.requestPossible.Load(), durationMS: uint64(time.Since(started).Milliseconds())}
	var failure *InferenceError
	var data []byte
	switch {
	case admitErr != nil:
		failure = inferenceFailure(admitErr, request.ID)
	case auditFailed.Load():
		failure = &InferenceError{Status: 503, Code: "inference_audit"}
		if outcome.dispatched {
			outcome.state = "uncertain"
		}
	case fetchErr != nil:
		var problem *EgressError
		if !errors.As(fetchErr, &problem) {
			problem = &EgressError{Status: 502, Code: "egress_upstream"}
		}
		failure = &InferenceError{Status: problem.Status, Code: "inference_" + strings.TrimPrefix(problem.Code, "egress_")}
		if outcome.dispatched && problem.Code != "egress_response_limit" {
			outcome.state = "uncertain"
		}
	case result.Status < 200 || result.Status > 299:
		code := "inference_status"
		if result.Status >= 300 && result.Status <= 399 {
			code = "inference_redirect"
		}
		failure = &InferenceError{Status: 502, Code: code}
	default:
		mediaType, _, mediaErr := mime.ParseMediaType(http.Header(result.Headers).Get("Content-Type"))
		data, err = base64.StdEncoding.DecodeString(result.BodyBase64)
		if err != nil || mediaErr != nil || mediaType != "application/json" && !(strings.HasPrefix(mediaType, "application/") && strings.HasSuffix(mediaType, "+json")) ||
			!utf8.Valid(data) || !json.Valid(data) {
			failure = &InferenceError{Status: 502, Code: "inference_response_json"}
		} else {
			outcome.state = "succeeded"
		}
	}
	if failure != nil {
		outcome.code = failure.Code
	}
	bill, err := e.ledger.finish(binding, request.ID, outcome)
	if err != nil {
		e.fail()
		return InferenceInvokeResult{}, inferenceFailure(inferenceError(503, "inference_store"), request.ID)
	}
	var receipt InferenceInvocationReceipt
	for _, invocation := range bill.Invocations {
		if invocation.ID == request.ID {
			receipt = invocation
			break
		}
	}
	event.Event, event.Code, event.Status, event.DurationMS = "infer.complete", receipt.Code, receipt.HTTPStatus, int64(receipt.DurationMS)
	if receipt.Dispatched {
		event.RequestBytes = int(receipt.InputBytes)
	}
	event.ResponseBytes = int(receipt.OutputBytes)
	event.Inference = &InferenceAuditMeter{State: receipt.State, ReservedUnits: receipt.ReservedUnits, SettledUnits: receipt.SettledUnits}
	if receipt.State == "uncertain" {
		event.Inference.HeldUnits = receipt.ReservedUnits
	}
	if admitErr == nil {
		if err := e.appendAudit(event); err != nil {
			return InferenceInvokeResult{}, inferenceFailure(err, request.ID)
		}
	}
	if failure != nil {
		return InferenceInvokeResult{}, inferenceFailure(failure, request.ID)
	}
	return InferenceInvokeResult{Protocol: "osv-sandbox-inference-invoke/v1", TaskID: binding.TaskID, Invocation: receipt, Data: json.RawMessage(data)}, nil
}
