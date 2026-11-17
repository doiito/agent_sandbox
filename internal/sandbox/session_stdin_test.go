package sandbox

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestCommandInputJournalBoundsAndLifecycle(t *testing.T) {
	id := strings.Repeat("b", 24)
	r := &commandRecord{info: SessionCommandInfo{ID: id, State: "running", InteractiveStdin: true}, input: make(chan linuxCommandInput, 1)}
	s := &Session{info: SessionInfo{ID: strings.Repeat("a", 24)}, commands: map[string]*commandRecord{id: r}}
	bytes := []byte{0, 255, 13, 10}
	request := SessionCommandInputRequest{DataBase64: base64.StdEncoding.EncodeToString(bytes)}
	receipt, err := s.SubmitCommandInput(id, request)
	if err != nil || receipt.State != "pending" || receipt.Sequence != 1 {
		t.Fatalf("admission: %+v %v", receipt, err)
	}
	if _, err = s.SubmitCommandInput(id, request); !errors.Is(err, ErrBusy) {
		t.Fatal("second input bypassed credit", err)
	}
	if frame := <-r.input; frame.Sequence != 1 || frame.DataBase64 != request.DataBase64 {
		t.Fatal("input changed")
	}
	if err = r.acknowledgeInput(linuxCommandInputAck{Sequence: 1, WrittenBytes: len(bytes)}); err != nil {
		t.Fatal(err)
	}
	delivered, err := s.PollCommandInput(id, 1)
	if err != nil || delivered.State != "delivered" || delivered.WrittenBytes != len(bytes) {
		t.Fatal("ack missing", delivered, err)
	}
	delivered.State = "corrupted"
	delivered, _ = s.PollCommandInput(id, 1)
	if delivered.State != "delivered" {
		t.Fatal("reader changed receipt")
	}
	receipt, err = s.SubmitCommandInput(id, SessionCommandInputRequest{Close: true})
	if err != nil {
		t.Fatal(err)
	}
	<-r.input
	if err = r.acknowledgeInput(linuxCommandInputAck{Sequence: receipt.Sequence, Closed: true}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.SubmitCommandInput(id, request); !errors.Is(err, ErrStdinClosed) {
		t.Fatal("write after EOF", err)
	}
	receipt, err = s.SubmitCommandInput(id, SessionCommandInputRequest{Close: true})
	if err != nil || receipt.State != "closed" || len(r.input) != 0 {
		t.Fatal("repeat close", receipt, err)
	}
	r.info.StdinClosed = false
	r.inputBytes = commandInputByteLimit
	if _, err = s.SubmitCommandInput(id, request); !errors.Is(err, ErrStdinLimit) {
		t.Fatal("byte quota bypass", err)
	}
	r.inputBytes = 0
	r.inputReceipts = make([]SessionCommandInputReceipt, commandInputRequestLimit)
	if _, err = s.SubmitCommandInput(id, request); !errors.Is(err, ErrStdinLimit) {
		t.Fatal("transaction quota bypass", err)
	}
	r.info.InteractiveStdin = false
	if _, err = s.SubmitCommandInput(id, request); !errors.Is(err, ErrStdinUnavailable) {
		t.Fatal("disabled stdin", err)
	}
	for _, invalid := range []SessionCommandInputRequest{{DataBase64: "Zg==\n"}, {DataBase64: "%%"}, {DataBase64: "Zg==", Close: true}, {DataBase64: strings.Repeat("A", 23000)}} {
		if _, err := invalid.data(); err == nil {
			t.Fatal("invalid data accepted")
		}
	}
}
func TestStreamedBackendInputAcknowledgementsAndCancel(t *testing.T) {
	for _, bad := range []string{"valid", "sequence", "bytes", "job", "nonce", "unsolicited"} {
		t.Run(bad, func(t *testing.T) {
			input := make(chan linuxCommandInput, 1)
			input <- linuxCommandInput{Sequence: 1, DataBase64: "AP8="}
			cancel := make(chan struct{})
			acked := 0
			b, work := streamBackendFixture(t, func(conn net.Conn, reader *bufio.Reader, request linuxJobRequest) {
				fmt.Fprintf(conn, "FC_AGENT_STARTED {\"protocol\":\"%s\",\"job_id\":\"%s\",\"pid\":42}\n", request.Protocol, request.JobID)
				var frame linuxCommandInput
				line, err := reader.ReadBytes('\n')
				if err != nil || json.Unmarshal(line, &frame) != nil {
					return
				}
				if frame.Protocol != request.Protocol || frame.JobID != request.JobID || frame.Sequence != 1 || frame.DataBase64 != "AP8=" {
					return
				}
				ack := linuxCommandInputAck{Protocol: request.Protocol, JobID: request.JobID, Sequence: 1, WrittenBytes: 2}
				switch bad {
				case "sequence":
					ack.Sequence = 2
				case "bytes":
					ack.WrittenBytes = 1
				case "job":
					ack.JobID = strings.Repeat("c", 24)
				case "nonce":
					ack.Binding = &linuxGuestBinding{SessionID: strings.Repeat("d", 24), Nonce: strings.Repeat("e", 64)}
				}
				data, _ := json.Marshal(ack)
				fmt.Fprintf(conn, "FC_AGENT_STDIN %s\n", data)
				if bad != "valid" {
					return
				}
				line, err = reader.ReadBytes('\n')
				if err != nil || string(line) != "cancel\n" {
					return
				}
				fmt.Fprintf(conn, "FC_AGENT_RESULT {\"protocol\":\"%s\",\"job_id\":\"%s\",\"ok\":false,\"exit_code\":137,\"timed_out\":false,\"stdout\":\"\",\"stderr\":\"\"}\n", request.Protocol, request.JobID)
			})
			if bad == "unsolicited" { /* Interactive flag must authorize acknowledgements too. */
			}
			ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
			defer stop()
			_, _, err := b.ExchangeSession(ctx, linuxJobRequest{JobID: strings.Repeat("a", 24), Operation: "run_stream", Argv: []string{"/bin/bash"}, TimeoutMS: 1000, InteractiveStdin: bad != "unsolicited", commandInput: input, commandCancel: cancel, onInputAck: func(ack linuxCommandInputAck) error { acked++; close(cancel); return nil }}, work)
			if bad == "valid" {
				if err != nil || acked != 1 {
					t.Fatal("valid input/cancel failed", err, acked)
				}
			} else if err == nil || acked != 0 {
				t.Fatal("invalid ack accepted", bad, err, acked)
			}
		})
	}
}
