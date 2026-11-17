package sandbox

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"
)

// A context deadline's timer callback may be scheduled after a socket with
// the same deadline has already returned its timeout. Control that ordering.
type delayedDeadlineContext struct {
	context.Context
	deadline time.Time
	done     chan struct{}
}

func (c *delayedDeadlineContext) Deadline() (time.Time, bool) { return c.deadline, true }
func (c *delayedDeadlineContext) Done() <-chan struct{}       { return c.done }
func (c *delayedDeadlineContext) Err() error {
	select {
	case <-c.done:
		return context.Canceled
	default:
		return nil
	}
}

func TestOSvPreparedJobSocketDeadlineBeforeContextCallback(t *testing.T) {
	for _, scenario := range []string{"elapsed-context-deadline", "acquire-at-deadline", "early-transport-timeout", "truncated-result", "caller-cancel"} {
		t.Run(scenario, func(t *testing.T) {
			m, backend := coldInputManager(t)
			parent := &delayedDeadlineContext{Context: context.Background(), deadline: time.Now().Add(5 * time.Second), done: make(chan struct{})}
			defer func() {
				select {
				case <-parent.done:
				default:
					close(parent.done)
				}
			}()
			backend.run = func(ctx context.Context) (json.RawMessage, bool, error) {
				if scenario == "truncated-result" {
					return nil, false, io.ErrUnexpectedEOF
				}
				if scenario == "caller-cancel" {
					close(parent.done)
					<-ctx.Done()
					return nil, false, net.ErrClosed
				}
				reader, writer := net.Pipe()
				defer reader.Close()
				defer writer.Close()
				deadline, ok := ctx.Deadline()
				if !ok {
					return nil, false, io.ErrNoProgress
				}
				if scenario == "early-transport-timeout" {
					deadline = time.Now().Add(time.Millisecond)
				}
				if err := reader.SetReadDeadline(deadline); err != nil {
					return nil, false, err
				}
				var data [1]byte
				_, err := reader.Read(data[:])
				return nil, false, err
			}
			if scenario == "elapsed-context-deadline" || scenario == "acquire-at-deadline" {
				parent.deadline = time.Now().Add(2 * time.Second)
			}
			if scenario == "acquire-at-deadline" {
				backend.prepare = func(pristinePreparation, string) error {
					time.Sleep(time.Until(parent.deadline))
					return io.ErrUnexpectedEOF
				}
			}
			result, err := m.Run(parent, RunRequest{Entrypoint: "/task-probe.so", TimeoutMS: 10000, tenantID: "tenant-a"})
			want := "protocol_error"
			if scenario == "elapsed-context-deadline" || scenario == "acquire-at-deadline" {
				want = "timed_out"
			} else if scenario == "caller-cancel" {
				want = "cancelled"
			}
			wantRuns := 1
			if scenario == "acquire-at-deadline" {
				wantRuns = 0
			}
			if err != nil || result.State != want || result.TimedOut != (want == "timed_out") || backend.ran != wantRuns {
				t.Fatalf("%s: state=%s timed_out=%t ran=%d err=%v", scenario, result.State, result.TimedOut, backend.ran, err)
			}
			if m.Capacity().Active != 0 || m.Capacity().Instances != 0 || len(m.VMInstances().States) != 0 {
				t.Fatal("deadline result retained VM ownership or capacity", m.Capacity(), m.VMInstances())
			}
		})
	}
}
