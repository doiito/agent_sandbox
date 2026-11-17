package controlgrpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	controlv1 "github.com/doiito/agent_sandbox/api/control/v1"
	"github.com/doiito/agent_sandbox/internal/sandbox"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"net/http/httptest"
	"strings"
)

func TestBridgeCommandEventsAndCancellation(t *testing.T) {
	for _, mode := range []string{"complete", "timeout", "cancel", "missing"} {
		t.Run(mode, func(t *testing.T) {
			_, connection, _ := bridgeForTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("after") != "0" || r.Header.Get("Authorization") != "Bearer "+fixtureToken {
					t.Error("stream request binding changed")
				}
				if mode == "missing" {
					w.WriteHeader(404)
					_, _ = io.WriteString(w, `{"code":"not_found","error":"command missing"}`)
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				control := http.NewResponseController(w)
				emit := func(kind string, value any) error {
					data, _ := json.Marshal(value)
					_, err := fmt.Fprintf(w, "id: 1\nevent: %s\ndata: %s\n\n", kind, data)
					if err == nil {
						err = control.Flush()
					}
					return err
				}
				if err := emit("output", sandbox.SessionOutputFrame{SessionID: fixtureID, CommandID: fixtureID,
					SessionOutputEvent: sandbox.SessionOutputEvent{Sequence: 1, Stream: "stdout", DataBase64: "AP8="}}); err != nil {
					return
				}
				switch mode {
				case "cancel":
					<-r.Context().Done()
				case "timeout":
					_ = emit("timeout", sandbox.SessionCommandTimeoutFrame{SessionID: fixtureID, CommandID: fixtureID, NextSequence: 1})
				default:
					_ = emit("result", sandbox.SessionCommandPage{Complete: true, NextSequence: 1,
						Info: sandbox.SessionCommandInfo{ID: fixtureID, SessionID: fixtureID, State: "completed", Args: []string{}}, Events: []sandbox.SessionOutputEvent{}})
				}
			}))
			ctx, cancel := authContext(t)
			defer cancel()
			stream, err := controlv1.NewControlClient(connection).StreamSessionCommand(ctx, &controlv1.StreamSessionCommandRequest{
				Id: proto.String(fixtureID), Command: proto.String(fixtureID), After: proto.Uint64(0)})
			if err != nil {
				t.Fatal(err)
			}
			first, err := stream.Recv()
			if mode == "missing" {
				if status.Code(err) != codes.NotFound {
					t.Fatalf("initial stream error changed: %v", err)
				}
				return
			}
			if err != nil || first.GetSequence() != 1 || !bytes.Equal(first.GetOutput().GetDataBase64(), []byte{0, 255}) {
				t.Fatalf("output event changed: %v %v", first, err)
			}
			if mode == "cancel" {
				cancel()
				if _, err := stream.Recv(); status.Code(err) != codes.Canceled {
					t.Fatalf("cancel: %v", err)
				}
				return
			}
			last, err := stream.Recv()
			if err != nil || mode == "complete" && !last.GetResult().GetComplete() || mode == "timeout" && last.GetTimeout() == nil {
				t.Fatalf("terminal event changed: %v %v", last, err)
			}
			if _, err := stream.Recv(); err != io.EOF {
				t.Fatalf("missing successful stream end: %v", err)
			}
		})
	}
}

type lifetimeWriter struct {
	http.ResponseWriter
	returned atomic.Bool
	late     *atomic.Int64
}

func (w *lifetimeWriter) Flush() { _ = http.NewResponseController(w.ResponseWriter).Flush() }
func (w *lifetimeWriter) SetWriteDeadline(deadline time.Time) error {
	if w.returned.Load() {
		w.late.Add(1)
		return nil
	}
	return http.NewResponseController(w.ResponseWriter).SetWriteDeadline(deadline)
}
func (w *lifetimeWriter) SetReadDeadline(deadline time.Time) error {
	if w.returned.Load() {
		w.late.Add(1)
		return nil
	}
	return http.NewResponseController(w.ResponseWriter).SetReadDeadline(deadline)
}

func TestBridgeJoinsApplicationBeforeHTTPWriterReuse(t *testing.T) {
	entered, completed := make(chan struct{}), make(chan struct{})
	var late atomic.Int64
	bridge, err := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		time.Sleep(25 * time.Millisecond)
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now())
		close(completed)
	}), sandbox.NewSingleTokenAuthenticator(fixtureToken))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		guard := &lifetimeWriter{ResponseWriter: w, late: &late}
		bridge.ServeHTTP(guard, r)
		guard.returned.Store(true)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	tls := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	connection, err := grpc.NewClient(strings.TrimPrefix(server.URL, "https://"), grpc.WithTransportCredentials(credentials.NewTLS(tls)), grpc.WithNoProxy())
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	defer func() {
		_ = connection.Close()
		server.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := bridge.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := authContext(t)
	defer cancel()
	stream, err := controlv1.NewControlClient(connection).StreamSessionCommand(ctx, &controlv1.StreamSessionCommandRequest{Id: proto.String(fixtureID), Command: proto.String(fixtureID)})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cancel()
	_, _ = stream.Recv()
	select {
	case <-completed:
	case <-time.After(time.Second):
		t.Fatal("application did not finish after cancellation")
	}
	if late.Load() != 0 {
		t.Fatal("application accessed response writer after HTTP handler returned")
	}
}

func portFixture(t *testing.T, mode string, active *atomic.Int64) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		active.Add(1)
		defer active.Add(-1)
		if r.ProtoMajor != 1 || r.Header.Get("Upgrade") != "osv-port/1" {
			t.Error("port did not use its actual bounded upgrade protocol")
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: osv-port/1\r\nX-OSV-Session-ID: %s\r\nX-OSV-Connection-ID: %s\r\nX-OSV-Port: 8080\r\n\r\n", fixtureID, fixtureID)
		if rw.Flush() != nil {
			return
		}
		finish := func(state string) {
			data, _ := json.Marshal(sandbox.SessionPortInfo{ID: fixtureID, Port: 8080, Status: state, SentBytes: 3, ReceivedBytes: 3})
			var header [5]byte
			header[0] = 4
			binary.BigEndian.PutUint32(header[1:], uint32(len(data)))
			_, _ = conn.Write(header[:])
			_, _ = conn.Write(data)
		}
		for {
			var header [5]byte
			if _, err := io.ReadFull(rw, header[:]); err != nil {
				return
			}
			size := binary.BigEndian.Uint32(header[1:])
			if size > 16384 {
				t.Error("oversized data reached the shared port owner")
				return
			}
			data := make([]byte, size)
			if _, err := io.ReadFull(rw, data); err != nil {
				return
			}
			switch header[0] {
			case 1:
				_, _ = conn.Write(header[:])
				_, _ = conn.Write(data)
				if mode == "server-finishes" {
					finish("completed")
					return
				}
			case 2:
				_, _ = conn.Write([]byte{2, 0, 0, 0, 0})
				finish("completed")
				return
			case 3:
				finish("cancelled")
				return
			default:
				t.Errorf("invalid native port frame %d", header[0])
				return
			}
		}
	})
}

func TestBridgePortDuplexOwnership(t *testing.T) {
	for _, mode := range []string{"half-close", "explicit-eof", "server-finishes", "cancel-frame", "cancel-context", "oversized", "stop"} {
		t.Run(mode, func(t *testing.T) {
			var active atomic.Int64
			bridge, connection, _ := bridgeForTest(t, portFixture(t, mode, &active))
			ctx, cancel := authContext(t)
			defer cancel()
			stream, err := controlv1.NewControlClient(connection).OpenPortTunnel(ctx)
			if err != nil {
				t.Fatal(err)
			}
			request := &controlv1.PortClientFrame{Frame: &controlv1.PortClientFrame_Open{Open: &controlv1.OpenPortTunnelRequest{
				Id: proto.String(fixtureID), Connection: proto.String(fixtureID), Port: proto.Uint64(8080), Body: &controlv1.SessionPortLimitsInput{
					MaxBytes: proto.Uint64(1024), TimeoutMs: proto.Uint64(1000), IdleTimeoutMs: proto.Uint64(1000)}}}}
			if err := stream.Send(request); err != nil {
				t.Fatal(err)
			}
			opened, err := stream.Recv()
			if err != nil || opened.GetOpened().GetConnection() != fixtureID {
				t.Fatalf("open acknowledgement: %v %v", opened, err)
			}
			if mode == "cancel-context" {
				cancel()
				if _, err := stream.Recv(); status.Code(err) != codes.Canceled {
					t.Fatalf("context cancel: %v", err)
				}
			} else if mode == "stop" {
				stopCtx, stop := context.WithTimeout(context.Background(), 2*time.Second)
				defer stop()
				if err := bridge.Shutdown(stopCtx); err != nil {
					t.Fatal(err)
				}
				if _, err := stream.Recv(); status.Code(err) != codes.Canceled {
					t.Fatalf("stop: %v", err)
				}
			} else if mode == "cancel-frame" {
				if err := stream.Send(&controlv1.PortClientFrame{Frame: &controlv1.PortClientFrame_Cancel{Cancel: &controlv1.TransportEmpty{}}}); err != nil {
					t.Fatal(err)
				}
				last, err := stream.Recv()
				if err != nil || last.GetFinished().GetStatus() != "cancelled" {
					t.Fatalf("cancel frame: %v %v", last, err)
				}
				if _, err := stream.Recv(); err != io.EOF {
					t.Fatal(err)
				}
			} else {
				data := []byte{0, 255, 1}
				if mode == "oversized" {
					data = make([]byte, 16385)
				}
				if err := stream.Send(&controlv1.PortClientFrame{Frame: &controlv1.PortClientFrame_Data{Data: data}}); err != nil {
					t.Fatal(err)
				}
				echo, err := stream.Recv()
				if mode == "oversized" {
					if status.Code(err) != codes.InvalidArgument {
						t.Fatalf("oversized frame accepted: %v", err)
					}
				} else {
					if err != nil || !bytes.Equal(echo.GetData(), data) {
						t.Fatalf("binary echo changed: %v %v", echo, err)
					}
					if mode != "server-finishes" {
						if mode == "explicit-eof" {
							_ = stream.Send(&controlv1.PortClientFrame{Frame: &controlv1.PortClientFrame_Eof{Eof: &controlv1.TransportEmpty{}}})
						}
						if err := stream.CloseSend(); err != nil {
							t.Fatal(err)
						}
						eof, err := stream.Recv()
						if err != nil || eof.GetEof() == nil {
							t.Fatalf("half-close event lost: %v %v", eof, err)
						}
					}
					last, err := stream.Recv()
					if err != nil || last.GetFinished().GetStatus() != "completed" {
						t.Fatalf("finish: %v %v", last, err)
					}
					if _, err := stream.Recv(); err != io.EOF {
						t.Fatal(err)
					}
				}
			}
			workers := make(chan struct{})
			go func() { bridge.workers.Wait(); close(workers) }()
			select {
			case <-workers:
			case <-time.After(time.Second):
				t.Fatal("owned port worker survived the completed/canceled RPC")
			}
			if active.Load() != 0 {
				t.Fatal("shared port handler survived RPC")
			}
		})
	}
}

func TestBridgeCancelsPendingStreamHandshake(t *testing.T) {
	var calls atomic.Int64
	bridge, connection, _ := bridgeForTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	ctx, cancel := authContext(t)
	defer cancel()
	stream, err := controlv1.NewControlClient(connection).OpenPortTunnel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream
	deadline := time.Now().Add(time.Second)
	for {
		bridge.mu.Lock()
		started := len(bridge.streams) == 1
		bridge.mu.Unlock()
		if started {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pending stream was not established")
		}
		time.Sleep(time.Millisecond)
	}
	stopCtx, stop := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer stop()
	if err := bridge.Shutdown(stopCtx); err != nil {
		t.Fatalf("pending handshake prevented graceful stop: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("no-message stream reached business admission")
	}
}
