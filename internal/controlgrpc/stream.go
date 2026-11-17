package controlgrpc

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	controlv1 "github.com/doiito/agent_sandbox/api/control/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type sseWriter struct {
	*responseCapture
	bridge   *Bridge
	stream   grpc.ServerStream
	ctx      context.Context
	terminal bool
}

func receiveFirst(ctx context.Context, stream grpc.ServerStream, message proto.Message) error {
	control := controlFor(ctx)
	if control == nil {
		return rpcFailure(codes.Unavailable, "unavailable", 503, "")
	}
	handshake, cancel := context.WithTimeout(ctx, 10*time.Second)
	deadline, _ := handshake.Deadline()
	_ = control.setDeadline(true, deadline)
	stopped := make(chan struct{})
	stop := context.AfterFunc(handshake, func() {
		defer close(stopped)
		_ = control.setDeadline(true, time.Now())
	})
	err := stream.RecvMsg(message)
	if !stop() {
		<-stopped
	}
	timedOut := handshake.Err() != nil || err != nil && !time.Now().Before(deadline)
	cancel()
	if ctx.Err() != nil {
		return status.FromContextError(ctx.Err()).Err()
	}
	if timedOut {
		return rpcFailure(codes.DeadlineExceeded, "timeout", 408, "")
	}
	if err != nil {
		return rpcFailure(codes.InvalidArgument, "invalid_request", 400, "")
	}
	clearReadDeadline(ctx)
	return nil
}

func (w *sseWriter) SetWriteDeadline(deadline time.Time) error {
	writeDeadline(w.ctx, deadline)
	return nil
}

func (w *sseWriter) FlushError() error {
	for {
		data := w.data.Bytes()
		boundary := bytes.Index(data, []byte("\n\n"))
		if boundary < 0 {
			return w.err
		}
		frame := append([]byte(nil), data[:boundary]...)
		w.data.Next(boundary + 2)
		if len(frame) == 0 || frame[0] == ':' {
			continue
		}
		if w.terminal {
			w.err = errors.New("event after terminal frame")
			return w.err
		}
		var id, kind string
		var payload []byte
		for _, line := range bytes.Split(frame, []byte("\n")) {
			key, value, found := strings.Cut(string(line), ":")
			if !found {
				w.err = errors.New("malformed command event")
				return w.err
			}
			value = strings.TrimPrefix(value, " ")
			switch key {
			case "id":
				id = value
			case "event":
				kind = value
			case "data":
				if len(payload) != 0 {
					payload = append(payload, '\n')
				}
				payload = append(payload, value...)
			default:
				w.err = errors.New("unknown command event metadata")
				return w.err
			}
		}
		sequence, err := strconv.ParseUint(id, 10, 64)
		if err != nil || strconv.FormatUint(sequence, 10) != id {
			w.err = errors.New("invalid command event sequence")
			return w.err
		}
		name := map[string]string{"output": "SessionOutputFrameOutput", "result": "SessionCommandPageOutput", "timeout": "SessionCommandTimeoutFrameOutput"}[kind]
		if name == "" {
			w.err = errors.New("unknown command event")
			return w.err
		}
		value, err := w.bridge.codec.fromJSON(name, payload)
		if err != nil {
			w.err = err
			return err
		}
		message := &controlv1.SessionCommandStreamEvent{Sequence: proto.Uint64(sequence)}
		field := message.ProtoReflect().Descriptor().Fields().ByName(protoreflect.Name(kind))
		message.ProtoReflect().Set(field, protoreflect.ValueOfMessage(value.ProtoReflect()))
		if err := w.bridge.send(w.ctx, w.stream, message); err != nil {
			w.err = err
			return err
		}
		w.terminal = kind == "result" || kind == "timeout"
	}
}

func (b *Bridge) sse(name string, stream grpc.ServerStream) error {
	ctx, done, err := b.begin(stream.Context(), true)
	if err != nil {
		return err
	}
	defer done()
	requestMessage := b.codec.newMessage(b.codec.spec.Operations[name].Request)
	if err := receiveFirst(ctx, stream, requestMessage); err != nil {
		return err
	}
	request, err := b.request(ctx, name, requestMessage)
	if err != nil {
		return err
	}
	if err := commit(ctx); err != nil {
		return err
	}
	writer := &sseWriter{responseCapture: newCapture(), bridge: b, stream: stream, ctx: ctx}
	b.http.ServeHTTP(writer, request)
	if writer.code == 0 {
		writer.code = http.StatusOK
	}
	grpc.SetTrailer(ctx, metadata.Pairs("osv-http-status", strconv.Itoa(writer.code)))
	if ctx.Err() != nil {
		return status.FromContextError(ctx.Err()).Err()
	}
	if writer.code >= 400 {
		return errorFromHTTP(writer.responseCapture)
	}
	if writer.err != nil || writer.data.Len() != 0 || !writer.terminal {
		return rpcFailure(codes.Internal, "incomplete_stream", 500, "")
	}
	return nil
}
