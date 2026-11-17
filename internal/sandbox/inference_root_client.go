package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unicode/utf8"
)

type inferenceRootClient struct{ model, control *http.Client }

func newInferenceRootClient(mainSocket string) *inferenceRootClient {
	return &inferenceRootClient{model: inferenceRootHTTP(mainSocket, 35*time.Second),
		control: inferenceRootHTTP(inferenceControlSocketPath(mainSocket), 8*time.Second)}
}

func inferenceRootHTTP(socket string, timeout time.Duration) *http.Client {
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 8192, ResponseHeaderTimeout: timeout}
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		if !filepath.IsAbs(socket) || filepath.Clean(socket) != socket {
			return nil, errors.New("invalid inference socket")
		}
		parent, err := os.Lstat(filepath.Dir(socket))
		if err != nil || !parent.IsDir() || parent.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("untrusted inference socket directory")
		}
		info, err := os.Lstat(socket)
		if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("untrusted inference socket")
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		parentOwner, parentOK := parent.Sys().(*syscall.Stat_t)
		if !ok || !parentOK || parentOwner.Uid != owner.Uid {
			return nil, errors.New("inference socket owner mismatch")
		}
		conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socket)
		if err != nil {
			return nil, errors.New("inference service unavailable")
		}
		peer, err := unixPeerCredential(conn.(*net.UnixConn))
		if err != nil || peer.Uid != owner.Uid {
			conn.Close()
			return nil, errors.New("inference service identity mismatch")
		}
		return conn, nil
	}
	return &http.Client{Transport: transport, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (c *inferenceRootClient) exchange(ctx context.Context, operation string, request inferenceRootRequest) ([]byte, error) {
	request.Protocol = inferenceRootProtocol
	data, err := marshalInferenceJSON(request)
	if err != nil {
		return nil, inferenceError(400, "inference_request")
	}
	req, err := http.NewRequestWithContext(ctx, "POST", "http://egress.invalid/v1/inference/root/"+operation, bytes.NewReader(data))
	if err != nil {
		return nil, inferenceError(400, "inference_request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.GetBody = nil
	client := c.control
	if operation == "invoke" {
		client = c.model
	}
	response, err := client.Do(req)
	if err != nil {
		id := ""
		if request.Invocation != nil {
			id = request.Invocation.ID
		}
		return nil, inferenceFailure(inferenceError(503, "inference_unavailable"), id)
	}
	defer response.Body.Close()
	data, err = io.ReadAll(io.LimitReader(response.Body, inferenceLedgerFileLimit+(64<<10)+1))
	if err != nil || len(data) > inferenceLedgerFileLimit+(64<<10) || !utf8.Valid(data) || !json.Valid(data) {
		return nil, inferenceError(503, "inference_protocol")
	}
	if response.StatusCode != 200 {
		var message struct {
			Protocol string         `json:"protocol"`
			Error    InferenceError `json:"error"`
		}
		if decodeInferenceJSON(data, &message) != nil || message.Protocol != "osv-sandbox-inference-error/v1" || !safeEgressCode(message.Error.Code) ||
			message.Error.InvocationID != "" && (request.Invocation == nil || message.Error.InvocationID != request.Invocation.ID) {
			return nil, inferenceError(503, "inference_protocol")
		}
		message.Error.Status = response.StatusCode
		return nil, &message.Error
	}
	return data, nil
}

func validateInferenceBill(bill InferenceBill, binding inferenceBinding) error {
	record := inferenceTaskRecord{Version: 1, Binding: binding, Closed: bill.Closed, MaxInvocations: bill.MaxInvocations,
		BudgetUnits: bill.BudgetUnits, Invocations: bill.Invocations}
	computed, err := record.bill()
	if err != nil || bill.Protocol != computed.Protocol || bill.Unit != computed.Unit || bill.Tenant != binding.Tenant ||
		bill.TaskID != binding.TaskID || bill.VMID != binding.VMID || bill.LeaseID != binding.LeaseID ||
		bill.SettledUnits != computed.SettledUnits || bill.HeldUnits != computed.HeldUnits {
		return inferenceError(503, "inference_protocol")
	}
	return nil
}

func (c *inferenceRootClient) task(ctx context.Context, operation string, binding inferenceBinding) (InferenceBill, error) {
	data, err := c.exchange(ctx, operation, inferenceRootRequest{Binding: binding})
	if err != nil {
		return InferenceBill{}, err
	}
	var reply inferenceRootReply
	if decodeInferenceJSON(data, &reply) != nil || reply.Protocol != inferenceRootProtocol || reply.Bill == nil ||
		len(reply.Record) != 0 || reply.Retired || reply.SHA256 != "" || validateInferenceBill(*reply.Bill, binding) != nil ||
		(operation == "close") != reply.Bill.Closed {
		return InferenceBill{}, inferenceError(503, "inference_protocol")
	}
	return *reply.Bill, nil
}

func (c *inferenceRootClient) invoke(ctx context.Context, binding inferenceBinding, request InferenceInvokeRequest, policy ...string) (InferenceInvokeResult, error) {
	wire := inferenceRootRequest{Binding: binding, Invocation: &request}
	if len(policy) > 1 {
		return InferenceInvokeResult{}, inferenceError(400, "inference_request")
	}
	if len(policy) == 1 {
		wire.PolicySHA256 = policy[0]
	}
	data, err := c.exchange(ctx, "invoke", wire)
	if err != nil {
		return InferenceInvokeResult{}, inferenceFailure(err, request.ID)
	}
	var result InferenceInvokeResult
	if decodeInferenceJSON(data, &result) != nil || result.ValidateForTask(binding.TaskID, request.ID, request.Endpoint) != nil {
		return InferenceInvokeResult{}, inferenceFailure(inferenceError(503, "inference_protocol"), request.ID)
	}
	return result, nil
}
