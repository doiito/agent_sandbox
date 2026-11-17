package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

func reservedInferenceRequest(request *http.Request) bool {
	return strings.EqualFold(request.URL.Hostname(), inferenceGuestHost)
}

// The binding and authorization come only from the kernel-verified root
// upgrade. Inner guest headers and JSON never select a tenant/task/VM/lease.
func (s *EgressServer) serveInferenceGuest(ctx context.Context, conn net.Conn, reader *bufio.Reader, request *http.Request, binding inferenceBinding, authorized bool) (int, string) {
	var result any
	var err error
	id := ""
	if !authorized || s.inference == nil {
		err = inferenceError(403, "inference_disabled")
	} else if request.URL.Scheme != "http" || request.URL.Port() != "" && request.URL.Port() != "80" ||
		request.URL.User != nil || request.URL.RawQuery != "" || request.URL.Fragment != "" ||
		!strings.EqualFold(request.Host, request.URL.Host) {
		err = inferenceError(400, "inference_request")
	} else if _, checkErr := s.inference.ledger.boundTask(binding, false); checkErr != nil {
		err = s.inference.lifecycleFailure(checkErr)
	} else {
		switch {
		case request.Method == "GET" && request.URL.Path == "/v1/bill":
			if request.ContentLength != 0 || len(request.TransferEncoding) != 0 {
				err = inferenceError(400, "inference_request")
			} else {
				result, err = s.inference.ledger.boundTask(binding, false)
			}
		case request.Method == "GET" && request.URL.Path == "/v1/policy":
			if request.ContentLength != 0 || len(request.TransferEncoding) != 0 {
				err = inferenceError(400, "inference_request")
			} else if tenant, tenantErr := s.inference.tenant(binding); tenantErr != nil {
				err = tenantErr
			} else if healthErr := s.inference.health(); healthErr != nil {
				err = healthErr
			} else {
				result = tenant.inference.capabilities()
			}
		case request.Method == "POST" && request.URL.Path == "/v1/invoke":
			var invocation InferenceInvokeRequest
			if err = readInferenceRequest(request, egressRequestLimit+8192, &invocation); err == nil {
				id = invocation.ID
				if _, checkErr := s.inference.ledger.boundTask(binding, true); checkErr != nil {
					err = s.inference.lifecycleFailure(checkErr)
				} else {
					// Include bytes already buffered past the body: pipelining and
					// EOF both cancel this one-request connection promptly.
					callCtx, cancel := context.WithCancel(ctx)
					watched := make(chan struct{})
					go func() {
						defer close(watched)
						var next [1]byte
						_, _ = reader.Read(next[:])
						cancel()
					}()
					result, err = s.inference.invokeFromGuest(callCtx, binding, invocation)
					_ = conn.SetReadDeadline(time.Now())
					<-watched
					cancel()
				}
			}
		default:
			err = inferenceError(404, "inference_not_found")
		}
	}
	status, code := 200, ""
	if err != nil {
		failure := inferenceFailure(err, id)
		status, code = failure.Status, failure.Code
		result = map[string]any{"protocol": "osv-sandbox-inference-error/v1", "error": failure}
	}
	data, marshalErr := marshalInferenceJSON(result)
	if marshalErr != nil {
		status, code = 503, "inference_protocol"
		data = []byte("{\"protocol\":\"osv-sandbox-inference-error/v1\",\"error\":{\"code\":\"inference_protocol\"}}\n")
	}
	response := &http.Response{StatusCode: status, ProtoMajor: 1, ProtoMinor: 1, Close: true,
		Header: http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}},
		Body:   io.NopCloser(bytes.NewReader(data)), ContentLength: int64(len(data)), Request: request}
	if response.Write(conn) != nil {
		return status, "inference_transport"
	}
	return status, code
}
