package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The response is visible to a client before its Write call returns. This is
// also possible with a pipe, but explicit handshakes make the race repeatable.
type handoffWriter struct {
	frames chan []byte
	resume chan struct{}
	closed chan struct{}
	once   sync.Once
}

func (w *handoffWriter) Write(data []byte) (int, error) {
	select {
	case w.frames <- append([]byte(nil), data...):
	case <-w.closed:
		return 0, io.ErrClosedPipe
	}
	select {
	case <-w.resume:
		return len(data), nil
	case <-w.closed:
		return 0, io.ErrClosedPipe
	}
}

func (w *handoffWriter) Close() error {
	w.once.Do(func() { close(w.closed) })
	return nil
}

func TestResponseHandoffReleasesAdmissionBeforeVisibleBytes(t *testing.T) {
	for _, control := range []bool{false, true} {
		for _, reuseID := range []bool{false, true} {
			t.Run(fmt.Sprintf("control=%t/reuse_id=%t", control, reuseID), func(t *testing.T) {
				_, _, bill := inferenceFixture(t)
				ctx, cancel := context.WithCancel(context.Background())
				firstStarted, firstRelease := make(chan struct{}), make(chan struct{})
				nextStarted := make(chan struct{}, 1)
				var first atomic.Bool
				first.Store(true)
				api := &apiClient{origin: "https://sandbox.invalid", token: "test-secret", http: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
					if first.CompareAndSwap(true, false) {
						close(firstStarted)
						select {
						case <-firstRelease:
						case <-r.Context().Done():
							return nil, r.Context().Err()
						}
						if control {
							return reply(bill), nil
						}
					}
					if r.URL.Path == "/v1/capabilities" {
						return reply(testCapabilities()), nil
					}
					nextStarted <- struct{}{}
					<-r.Context().Done()
					return nil, r.Context().Err()
				})}}
				writer := &handoffWriter{frames: make(chan []byte, 4), resume: make(chan struct{}, 4), closed: make(chan struct{})}
				c := &connection{server: newServer(api, 1), ctx: ctx, cancel: cancel, writer: writer,
					active: make(map[string]*activeRequest), slots: make(chan struct{}, 1), portControls: make(chan struct{}, 2),
					pending: make(chan output, 16), writerDone: make(chan struct{})}
				slots, occupied := c.slots, 0
				if control {
					slots, occupied = c.portControls, 1
					// One independent control call remains occupied throughout.
					slots <- struct{}{}
				}
				go c.writeLoop()
				t.Cleanup(func() {
					cancel()
					_ = writer.Close()
					await(t, c.writerDone)
					joined := make(chan struct{})
					go func() { c.wg.Wait(); close(joined) }()
					await(t, joined)
				})
				send := func(value any) {
					t.Helper()
					data, err := json.Marshal(value)
					if err != nil || !c.receive(data) {
						t.Fatal("request transport stopped", err)
					}
				}
				receive := func() map[string]any {
					t.Helper()
					select {
					case frame := <-writer.frames:
						var value map[string]any
						if err := json.Unmarshal(frame, &value); err != nil {
							t.Fatal(err)
						}
						return value
					case <-time.After(3 * time.Second):
						t.Fatal("response not written")
						return nil
					}
				}
				if control {
					send(modern(1, "tools/call", map[string]any{"name": "sandbox.ml.bill", "arguments": map[string]string{"task_id": bill.TaskID}}))
				} else {
					send(modern(1, "tools/list", nil))
				}
				await(t, firstStarted)
				c.mu.Lock()
				previous := c.active["n:1"]
				c.mu.Unlock()
				close(firstRelease)
				if response := receive(); response["error"] != nil || response["id"] != float64(1) {
					t.Fatal("first response failed", response)
				}
				id := 2
				if reuseID {
					id = 1
				}
				name, arguments := "sandbox.exec", map[string]string{"entrypoint": "/bin/sh"}
				if control {
					name, arguments = "sandbox.ml.bill", map[string]string{"task_id": strings.Repeat("f", 24)}
				}
				next := modern(id, "tools/call", map[string]any{"name": name, "arguments": arguments})
				send(next)
				select {
				case <-nextStarted:
				case rejected := <-c.pending:
					t.Fatalf("visible response retained admission: %s", rejected.data)
				case <-time.After(3 * time.Second):
					t.Fatal("next request did not enter API")
				}
				key := fmt.Sprintf("n:%d", id)
				c.mu.Lock()
				current := c.active[key]
				c.mu.Unlock()
				if previous == nil || current == nil || previous == current {
					t.Fatal("visible response retained old active request")
				}
				writer.resume <- struct{}{}
				await(t, previous.ctx.Done())
				c.mu.Lock()
				stillActive := c.active[key] == current
				c.mu.Unlock()
				if !stillActive || len(slots) != occupied+1 {
					t.Fatal("previous cleanup removed the new request or its slot")
				}
				send(next)
				if response := receive(); errorCode(t, response) != -32600 {
					t.Fatal("active duplicate was admitted", response)
				}
				writer.resume <- struct{}{}
				send(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]int{"requestId": id}})
				await(t, current.ctx.Done())
			})
		}
	}
}
