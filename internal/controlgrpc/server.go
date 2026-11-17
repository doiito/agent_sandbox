package controlgrpc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	controlv1 "github.com/doiito/agent_sandbox/api/control/v1"
	"github.com/doiito/agent_sandbox/internal/sandbox"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const servicePrefix = "/sandbox.control.v1.Control/"
const maxReceiveBytes = 1 << 20
const maxResponseBytes = 16 << 20
const sendTimeout = 5 * time.Second

type transportKey struct{}
type transportControl struct {
	controller      *http.ResponseController
	host            string
	remote          string
	mu              sync.Mutex
	started         bool
	closed          bool
	applicationDone chan struct{}
}

func (c *transportControl) applicationBegin() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started || c.closed {
		return false
	}
	c.started = true
	return true
}

func (c *transportControl) joinApplication() {
	c.mu.Lock()
	started := c.started
	if !started {
		c.closed = true
	}
	c.mu.Unlock()
	if started {
		<-c.applicationDone
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
	}
}

func (c *transportControl) setDeadline(read bool, deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return http.ErrNotSupported
	}
	if read {
		return c.controller.SetReadDeadline(deadline)
	}
	return c.controller.SetWriteDeadline(deadline)
}

// Bridge serves native protobuf gRPC and the existing HTTP control service on
// one TLS HTTP/2 listener. It owns every transport worker, but owns no VM pool.
type Bridge struct {
	http       http.Handler
	auth       *sandbox.Authenticator
	codec      *wireCodec
	server     *grpc.Server
	permits    chan struct{}
	mu         sync.Mutex
	closing    bool
	nextID     uint64
	calls      map[uint64]context.CancelFunc
	streams    map[uint64]context.CancelFunc
	transports map[uint64]context.CancelFunc
	httpActive sync.WaitGroup
	active     sync.WaitGroup
	workers    sync.WaitGroup
	stop       sync.Once
	done       chan struct{}
	stopErr    error
}

func New(handler http.Handler, auth *sandbox.Authenticator) (*Bridge, error) {
	codec, err := newWireCodec()
	if err != nil {
		return nil, err
	}
	b := &Bridge{http: handler, auth: auth, codec: codec, permits: make(chan struct{}, 64),
		calls: make(map[uint64]context.CancelFunc), streams: make(map[uint64]context.CancelFunc),
		transports: make(map[uint64]context.CancelFunc), done: make(chan struct{})}
	b.server = grpc.NewServer(grpc.MaxRecvMsgSize(maxReceiveBytes), grpc.MaxSendMsgSize(maxResponseBytes))
	description := grpc.ServiceDesc{ServiceName: "sandbox.control.v1.Control", HandlerType: (*interface{})(nil), Metadata: "api/control/v1/control.proto"}
	var names []string
	for name := range codec.spec.Operations {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		operation := codec.spec.Operations[name]
		if operation.ServerStreaming {
			description.Streams = append(description.Streams, grpc.StreamDesc{StreamName: name, ClientStreams: operation.ClientStreaming,
				ServerStreams: true, Handler: func(_ any, stream grpc.ServerStream) error {
					if operation.ClientStreaming {
						return b.port(stream)
					}
					return b.sse(name, stream)
				}})
		} else {
			description.Methods = append(description.Methods, grpc.MethodDesc{MethodName: name,
				Handler: func(_ any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
					request := codec.newMessage(operation.Request)
					if err := decode(request); err != nil {
						return nil, rpcFailure(codes.InvalidArgument, "invalid_request", 400, "")
					}
					invoke := func(ctx context.Context, request any) (any, error) {
						return b.unary(ctx, name, request.(proto.Message))
					}
					if interceptor == nil {
						return invoke(ctx, request)
					}
					return interceptor(ctx, request, &grpc.UnaryServerInfo{Server: b, FullMethod: servicePrefix + name}, invoke)
				}})
		}
	}
	b.server.RegisterService(&description, b)
	return b, nil
}

func (b *Bridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	media, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if !strings.HasPrefix(media, "application/grpc") && !strings.HasPrefix(r.URL.Path, servicePrefix) {
		b.http.ServeHTTP(w, r)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, servicePrefix)
	operation, known := b.codec.spec.Operations[name]
	known = known && r.URL.Path == servicePrefix+name
	if !known || name != "Health" && name != "Readiness" {
		if b.auth == nil {
			writeRPCFailure(w, rpcFailure(codes.Unavailable, "unavailable", 503, ""))
			return
		}
		if _, valid := b.auth.Authenticate(r.Header.Get("Authorization")); !valid || len(r.Header.Values("Authorization")) != 1 {
			writeRPCFailure(w, rpcFailure(codes.Unauthenticated, "unauthorized", 401, ""))
			return
		}
	}
	if mediaErr != nil || media != "application/grpc" && media != "application/grpc+proto" || r.ProtoMajor != 2 || r.Method != "POST" || r.URL.RawQuery != "" {
		writeRPCFailure(w, rpcFailure(codes.InvalidArgument, "invalid_transport", 400, ""))
		return
	}
	if !known {
		writeRPCFailure(w, rpcFailure(codes.Unimplemented, "unsupported", 501, ""))
		return
	}
	b.mu.Lock()
	if b.closing {
		b.mu.Unlock()
		writeRPCFailure(w, rpcFailure(codes.Unavailable, "unavailable", 503, ""))
		return
	}
	select {
	case b.permits <- struct{}{}:
		defer func() { <-b.permits }()
	default:
		b.mu.Unlock()
		writeRPCFailure(w, rpcFailure(codes.ResourceExhausted, "quota", 429, ""))
		return
	}
	control := &transportControl{controller: http.NewResponseController(w), host: r.Host, remote: r.RemoteAddr, applicationDone: make(chan struct{})}
	ctx, cancel := context.WithCancel(r.Context())
	b.nextID++
	id := b.nextID
	b.transports[id] = cancel
	b.httpActive.Add(1)
	b.mu.Unlock()
	ioStopped := make(chan struct{})
	stopIO := context.AfterFunc(ctx, func() {
		defer close(ioStopped)
		_ = control.setDeadline(true, time.Now())
		_ = control.setDeadline(false, time.Now())
		if r.Body != nil {
			_ = r.Body.Close()
		}
	})
	defer func() {
		// ServeHTTP may stop its transport before an application observer's
		// bounded cleanup has finished. Keep its writer alive until that work
		// has returned, then prevent all later controller access.
		control.joinApplication()
		// Join the callback before net/http may reuse its response writer.
		if !stopIO() {
			<-ioStopped
		}
		cancel()
		b.mu.Lock()
		delete(b.transports, id)
		b.mu.Unlock()
		b.httpActive.Done()
	}()
	if operation.ServerStreaming {
		// Receiving the first typed message remains bounded. The established
		// stream clears this and uses its existing business lifetime/idle limits.
		_ = control.setDeadline(true, time.Now().Add(10*time.Second))
	}
	b.server.ServeHTTP(w, r.WithContext(context.WithValue(ctx, transportKey{}, control)))
}

func (b *Bridge) begin(ctx context.Context, stream bool) (context.Context, func(), error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closing {
		return nil, nil, rpcFailure(codes.Unavailable, "unavailable", 503, "")
	}
	control := controlFor(ctx)
	if control == nil || !control.applicationBegin() {
		return nil, nil, rpcFailure(codes.Unavailable, "unavailable", 503, "")
	}
	ctx, cancel := context.WithCancel(ctx)
	b.nextID++
	id := b.nextID
	b.calls[id] = cancel
	if stream {
		b.streams[id] = cancel
	}
	b.active.Add(1)
	return ctx, func() {
		cancel()
		b.mu.Lock()
		delete(b.calls, id)
		delete(b.streams, id)
		b.mu.Unlock()
		close(control.applicationDone)
		b.active.Done()
	}, nil
}

func controlFor(ctx context.Context) *transportControl {
	control, _ := ctx.Value(transportKey{}).(*transportControl)
	return control
}

func writeDeadline(ctx context.Context, deadline time.Time) {
	if control := controlFor(ctx); control != nil {
		_ = control.setDeadline(false, deadline)
	}
}

func clearReadDeadline(ctx context.Context) {
	if control := controlFor(ctx); control != nil {
		_ = control.setDeadline(true, time.Time{})
	}
}

func commit(ctx context.Context) error {
	writeDeadline(ctx, time.Now().Add(sendTimeout))
	err := grpc.SendHeader(ctx, metadata.Pairs("osv-rpc-accepted", "1"))
	if err == nil {
		writeDeadline(ctx, time.Time{})
	}
	return err
}

func (b *Bridge) request(ctx context.Context, name string, message proto.Message) (*http.Request, error) {
	operation := b.codec.spec.Operations[name]
	value, err := b.codec.toValue(message.ProtoReflect(), 0)
	if err != nil {
		return nil, rpcFailure(codes.InvalidArgument, "invalid_request", 400, "")
	}
	object := value.(map[string]any)
	path, query := operation.Path, make(url.Values)
	var body []byte
	for key, field := range b.codec.spec.Messages[operation.OpenRequest].Fields {
		value, present := object[key]
		if !present {
			continue
		}
		switch field.Location {
		case "path":
			text := fmt.Sprint(value)
			if text == "." || text == ".." || strings.ContainsAny(text, "/\\\x00") {
				return nil, rpcFailure(codes.InvalidArgument, "invalid_request", 400, "")
			}
			path = strings.ReplaceAll(path, "{"+key+"}", url.PathEscape(text))
		case "query":
			query.Set(key, fmt.Sprint(value))
		case "body":
			body, err = json.Marshal(value)
		}
	}
	if err != nil || len(path)+len(query.Encode()) > 16<<10 {
		return nil, rpcFailure(codes.InvalidArgument, "invalid_request", 400, "")
	}
	if len(query) != 0 {
		path += "?" + query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, operation.Method, "http://control.invalid"+path, bytes.NewReader(body))
	if err != nil {
		return nil, rpcFailure(codes.InvalidArgument, "invalid_request", 400, "")
	}
	request.Proto, request.ProtoMajor, request.ProtoMinor = "HTTP/2.0", 2, 0
	request.Header.Set("Content-Type", "application/json")
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		for _, key := range []string{"authorization", "traceparent"} {
			if values := md.Get(key); len(values) == 1 {
				request.Header.Set(key, values[0])
			}
		}
	}
	control := controlFor(ctx)
	if control != nil && control.host != "" {
		request.Host = control.host
		request.RemoteAddr = control.remote
	}
	return request, nil
}

type responseCapture struct {
	headers http.Header
	code    int
	data    bytes.Buffer
	err     error
}

func newCapture() *responseCapture             { return &responseCapture{headers: make(http.Header)} }
func (w *responseCapture) Header() http.Header { return w.headers }
func (w *responseCapture) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
}
func (w *responseCapture) Write(data []byte) (int, error) {
	if w.code == 0 {
		w.code = 200
	}
	if w.data.Len()+len(data) > maxResponseBytes {
		w.err = errors.New("bounded response exceeded")
		return 0, w.err
	}
	return w.data.Write(data)
}

func (b *Bridge) unary(parent context.Context, name string, message proto.Message) (proto.Message, error) {
	ctx, done, err := b.begin(parent, false)
	if err != nil {
		return nil, err
	}
	defer done()
	defer func() { writeDeadline(ctx, time.Now().Add(sendTimeout)) }()
	request, err := b.request(ctx, name, message)
	if err != nil {
		return nil, err
	}
	if err := commit(ctx); err != nil {
		return nil, err
	}
	capture := newCapture()
	b.http.ServeHTTP(capture, request)
	if capture.code == 0 {
		capture.code = 200
	}
	grpc.SetTrailer(ctx, metadata.Pairs("osv-http-status", strconv.Itoa(capture.code)))
	if capture.err != nil {
		return nil, rpcFailure(codes.ResourceExhausted, "response_too_large", 413, "")
	}
	if ctx.Err() != nil {
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	operation := b.codec.spec.Operations[name]
	diagnostic := (name == "HostDoctor" || name == "Readiness") && capture.code == 503
	if capture.code >= 400 && !diagnostic {
		return nil, errorFromHTTP(capture)
	}
	if operation.Response == "MetricsText" {
		return &controlv1.MetricsText{Text: proto.String(capture.data.String())}, nil
	}
	if capture.code == 204 {
		return b.codec.newMessage(operation.Response), nil
	}
	response, err := b.codec.fromJSON(operation.Response, capture.data.Bytes())
	if err != nil {
		if diagnostic {
			return nil, errorFromHTTP(capture)
		}
		return nil, rpcFailure(codes.Internal, "invalid_response", 500, "")
	}
	return response, nil
}

func rpcFailure(code codes.Code, label string, httpStatus int, invocation string) error {
	if !validErrorLabel(label) {
		label = "api_error"
	}
	detail := &controlv1.ErrorDetail{Code: proto.String(label), Message: proto.String("control request: " + label), HttpStatus: proto.Uint64(uint64(httpStatus))}
	if len(invocation) == 24 && strings.Trim(invocation, "0123456789abcdef") == "" {
		detail.InvocationId = proto.String(invocation)
	}
	value, err := status.New(code, "control request: "+label).WithDetails(detail)
	if err != nil {
		return status.Error(codes.Internal, "control request failed")
	}
	return value.Err()
}

func validErrorLabel(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if char != '_' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}

func errorFromHTTP(capture *responseCapture) error {
	var body struct {
		Code       string `json:"code"`
		Invocation string `json:"invocation_id"`
	}
	_ = json.Unmarshal(capture.data.Bytes(), &body)
	code := codes.Unknown
	switch capture.code {
	case 400, 422:
		code = codes.InvalidArgument
	case 401:
		code = codes.Unauthenticated
	case 403:
		code = codes.PermissionDenied
	case 404:
		code = codes.NotFound
	case 405, 501:
		code = codes.Unimplemented
	case 408, 504:
		code = codes.DeadlineExceeded
	case 409, 410:
		code = codes.FailedPrecondition
	case 413, 429:
		code = codes.ResourceExhausted
	case 416:
		code = codes.OutOfRange
	case 500:
		code = codes.Internal
	case 502, 503:
		code = codes.Unavailable
	}
	return rpcFailure(code, body.Code, capture.code, body.Invocation)
}

func writeRPCFailure(w http.ResponseWriter, err error) {
	value := status.Convert(err)
	data, _ := proto.Marshal(value.Proto())
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Trailer", "Grpc-Status, Grpc-Message, Grpc-Status-Details-Bin")
	w.WriteHeader(200)
	w.Header().Set("Grpc-Status", strconv.Itoa(int(value.Code())))
	w.Header().Set("Grpc-Message", url.PathEscape(value.Message()))
	w.Header().Set("Grpc-Status-Details-Bin", base64.RawStdEncoding.EncodeToString(data))
}

func (b *Bridge) send(ctx context.Context, stream grpc.ServerStream, message proto.Message) error {
	writeDeadline(ctx, time.Now().Add(sendTimeout))
	err := stream.SendMsg(message)
	if err == nil {
		writeDeadline(ctx, time.Time{})
	}
	return err
}

func (b *Bridge) Shutdown(ctx context.Context) error {
	b.stop.Do(func() {
		b.mu.Lock()
		b.closing = true
		for _, cancel := range b.streams {
			cancel()
		}
		b.mu.Unlock()
		go func() {
			if owner, ok := b.http.(interface{ Shutdown(context.Context) error }); ok {
				b.stopErr = owner.Shutdown(ctx)
			}
			// grpc-go's ServeHTTP transport has no Drain implementation. Close
			// admission ourselves and wait for complete HTTP RPC lifetimes,
			// including readers that have not decoded a first message yet.
			drained := make(chan struct{})
			go func() { b.httpActive.Wait(); close(drained) }()
			select {
			case <-drained:
				b.server.Stop()
			case <-ctx.Done():
				b.mu.Lock()
				var cancelAll []context.CancelFunc
				for _, cancel := range b.transports {
					cancelAll = append(cancelAll, cancel)
				}
				b.mu.Unlock()
				for _, cancel := range cancelAll {
					cancel()
				}
				b.server.Stop()
				<-drained
				b.stopErr = errors.Join(b.stopErr, ctx.Err())
			}
			b.active.Wait()
			b.workers.Wait()
			close(b.done)
		}()
	})
	select {
	case <-b.done:
		return b.stopErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *Bridge) CloseTelemetry(ctx context.Context) error {
	err := b.Shutdown(ctx)
	if owner, ok := b.http.(interface{ CloseTelemetry(context.Context) error }); ok {
		err = errors.Join(err, owner.CloseTelemetry(ctx))
	}
	return err
}

var _ io.Writer = (*responseCapture)(nil)
