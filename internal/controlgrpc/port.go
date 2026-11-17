package controlgrpc

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	controlv1 "github.com/doiito/agent_sandbox/api/control/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type portWriter struct {
	*responseCapture
	mu       sync.Mutex
	closed   bool
	server   net.Conn
	client   net.Conn
	hijacked chan net.Conn
}

func (w *portWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.server != nil {
		return nil, nil, net.ErrClosed
	}
	w.server, w.client = net.Pipe()
	w.hijacked <- w.client
	return w.server, bufio.NewReadWriter(bufio.NewReader(w.server), bufio.NewWriter(w.server)), nil
}

func (w *portWriter) close() {
	w.mu.Lock()
	w.closed = true
	server, client := w.server, w.client
	w.mu.Unlock()
	if server != nil {
		_ = server.Close()
	}
	if client != nil {
		_ = client.Close()
	}
}

func writePortFrame(conn net.Conn, kind byte, data []byte) error {
	var header [5]byte
	header[0] = kind
	binary.BigEndian.PutUint32(header[1:], uint32(len(data)))
	for _, value := range [][]byte{header[:], data} {
		for len(value) > 0 {
			written, err := conn.Write(value)
			if err != nil {
				return err
			}
			if written == 0 {
				return io.ErrShortWrite
			}
			value = value[written:]
		}
	}
	return nil
}

func readPortFrame(reader io.Reader) (byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, nil, err
	}
	kind, size := header[0], binary.BigEndian.Uint32(header[1:])
	if kind == 1 && (size == 0 || size > 16384) || kind == 2 && size != 0 || kind == 4 && (size == 0 || size > 4096) || kind != 1 && kind != 2 && kind != 4 {
		return 0, nil, errors.New("invalid bounded server port frame")
	}
	data := make([]byte, size)
	_, err := io.ReadFull(reader, data)
	return kind, data, err
}

func (b *Bridge) port(stream grpc.ServerStream) error {
	parent, done, err := b.begin(stream.Context(), true)
	if err != nil {
		return err
	}
	defer done()
	first := &controlv1.PortClientFrame{}
	if err := receiveFirst(parent, stream, first); err != nil {
		return err
	}
	if first.GetOpen() == nil {
		return rpcFailure(codes.InvalidArgument, "invalid_request", 400, "")
	}
	ctx, cancel := context.WithCancel(parent)
	request, err := b.request(ctx, "OpenPortTunnel", first.GetOpen())
	if err != nil {
		cancel()
		return err
	}
	request.Proto, request.ProtoMajor, request.ProtoMinor = "HTTP/1.1", 1, 1
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "osv-port/1")
	if err := commit(ctx); err != nil {
		cancel()
		return err
	}
	writer := &portWriter{responseCapture: newCapture(), hijacked: make(chan net.Conn, 1)}
	stopClose := context.AfterFunc(ctx, writer.close)
	finished := make(chan struct{})
	b.workers.Add(1)
	go func() {
		defer b.workers.Done()
		defer close(finished)
		b.http.ServeHTTP(writer, request)
	}()
	defer func() {
		cancel()
		writer.close()
		stopClose()
		<-finished
	}()
	var conn net.Conn
	select {
	case conn = <-writer.hijacked:
	case <-finished:
		if writer.code >= 400 {
			return errorFromHTTP(writer.responseCapture)
		}
		return rpcFailure(codes.Unavailable, "port_transport", 503, "")
	case <-ctx.Done():
		return status.FromContextError(ctx.Err()).Err()
	}
	reader := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return rpcFailure(codes.Unavailable, "port_transport", 503, "")
	}
	open := first.GetOpen()
	if response.StatusCode != 101 || !strings.EqualFold(response.Header.Get("Upgrade"), "osv-port/1") ||
		response.Header.Get("X-OSV-Session-ID") != open.GetId() || response.Header.Get("X-OSV-Connection-ID") != open.GetConnection() ||
		response.Header.Get("X-OSV-Port") != strconv.FormatUint(open.GetPort(), 10) {
		return rpcFailure(codes.Unavailable, "port_transport", 503, "")
	}
	_ = conn.SetReadDeadline(time.Time{})
	ack := &controlv1.PortServerFrame{Frame: &controlv1.PortServerFrame_Opened{Opened: &controlv1.PortOpened{
		Id: proto.String(open.GetId()), Connection: proto.String(open.GetConnection()), Port: proto.Uint64(open.GetPort())}}}
	if err := b.send(ctx, stream, ack); err != nil {
		return err
	}
	received := make(chan error, 1)
	// RecvMsg is canceled by gRPC when this handler returns. It belongs to the
	// bridge-wide worker owner, which joins it after GracefulStop/Stop. Waiting
	// for it before returning would deadlock a client that never half-closes.
	b.workers.Add(1)
	go func() {
		defer b.workers.Done()
		err := receivePort(ctx, stream, conn)
		received <- err
		if err != nil {
			cancel()
			writer.close()
		}
	}()
	for {
		kind, data, err := readPortFrame(reader)
		if err != nil {
			select {
			case receiverErr := <-received:
				if receiverErr != nil {
					return receiverErr
				}
			default:
			}
			if ctx.Err() != nil {
				return status.FromContextError(ctx.Err()).Err()
			}
			return rpcFailure(codes.Unavailable, "incomplete_stream", 503, "")
		}
		frame := &controlv1.PortServerFrame{}
		switch kind {
		case 1:
			frame.Frame = &controlv1.PortServerFrame_Data{Data: data}
		case 2:
			frame.Frame = &controlv1.PortServerFrame_Eof{Eof: &controlv1.TransportEmpty{}}
		case 4:
			info, err := b.codec.fromJSON("SessionPortInfoOutput", data)
			if err != nil {
				return rpcFailure(codes.Unavailable, "invalid_response", 503, "")
			}
			frame.Frame = &controlv1.PortServerFrame_Finished{Finished: info.(*controlv1.SessionPortInfoOutput)}
		}
		if err := b.send(ctx, stream, frame); err != nil {
			return err
		}
		if kind == 4 {
			return nil
		}
	}
}

func receivePort(ctx context.Context, stream grpc.ServerStream, conn net.Conn) error {
	halfClosed := false
	for {
		frame := &controlv1.PortClientFrame{}
		err := stream.RecvMsg(frame)
		if ctx.Err() != nil {
			return status.FromContextError(ctx.Err()).Err()
		}
		if errors.Is(err, io.EOF) {
			if !halfClosed {
				return writePortFrame(conn, 2, nil)
			}
			return nil
		}
		if err != nil {
			return err
		}
		switch value := frame.Frame.(type) {
		case *controlv1.PortClientFrame_Data:
			if halfClosed || len(value.Data) < 1 || len(value.Data) > 16384 {
				return rpcFailure(codes.InvalidArgument, "invalid_request", 400, "")
			}
			if err := writePortFrame(conn, 1, value.Data); err != nil {
				return err
			}
		case *controlv1.PortClientFrame_Eof:
			if halfClosed {
				return rpcFailure(codes.InvalidArgument, "invalid_request", 400, "")
			}
			halfClosed = true
			if err := writePortFrame(conn, 2, nil); err != nil {
				return err
			}
		case *controlv1.PortClientFrame_Cancel:
			return writePortFrame(conn, 3, nil)
		default:
			return rpcFailure(codes.InvalidArgument, "invalid_request", 400, "")
		}
	}
}
