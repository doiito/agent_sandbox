package sandbox

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func codeBool(value bool) *bool     { return &value }
func codeText(value string) *string { return &value }
func testCodeContext() CodeContext {
	pid := uint32(42)
	return CodeContext{ID: strings.Repeat("c", 24), Generation: 1, Language: "python", Cwd: "/workspace", State: "idle", PID: &pid}
}
func TestCodeCommandsAreClosedUnionsAndPreserveZero(t *testing.T) {
	c := testCodeContext()
	eid := strings.Repeat("e", 24)
	for _, request := range []CodeCommand{
		{Operation: "create", ContextID: c.ID, Language: c.Language, Cwd: c.Cwd}, {Operation: "default", Language: "python"}, {Operation: "list"},
		{Operation: "info", ContextID: c.ID}, {Operation: "restart", ContextID: c.ID, Generation: 1}, {Operation: "remove", ContextID: c.ID, Generation: 1},
		{Operation: "execute", ContextID: c.ID, Generation: 1, ExecutionID: eid, Code: "42", Environment: map[string]string{}},
		{Operation: "execution", ExecutionID: eid}, {Operation: "cancel", ContextID: c.ID, Generation: 1, ExecutionID: eid},
	} {
		data, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		var decoded CodeCommand
		if err = json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(string(data), err)
		}
		if !reflect.DeepEqual(request, decoded) {
			t.Fatal(request, decoded)
		}
		if request.Operation == "execute" && (!strings.Contains(string(data), `"timeout_ms":0`) || !strings.Contains(string(data), `"environment":{}`)) {
			t.Fatal(string(data))
		}
		if request.Operation == "execution" && !strings.Contains(string(data), `"after":0`) {
			t.Fatal(string(data))
		}
		var extra map[string]json.RawMessage
		_ = json.Unmarshal(data, &extra)
		extra["extra"] = json.RawMessage(`false`)
		invalid, _ := json.Marshal(extra)
		if json.Unmarshal(invalid, &decoded) == nil {
			t.Fatal("unknown field accepted", string(invalid))
		}
	}
	for _, input := range []string{`{"operation":"list","generation":0}`, `{"operation":"default","language":"ruby"}`, `{"operation":"execution","execution_id":"` + eid + `"}`, `{"operation":"cancel","context_id":"` + c.ID + `","generation":1,"execution_id":null}`} {
		var request CodeCommand
		if json.Unmarshal([]byte(input), &request) == nil {
			t.Fatal("invalid union accepted", input)
		}
	}
}
func TestCodeInputBudgetsAndEnvironmentAreEnforced(t *testing.T) {
	r := CodeCommand{Operation: "execute", ContextID: strings.Repeat("c", 24), ExecutionID: strings.Repeat("e", 24), Generation: 1, Code: "42"}
	if r.Validate() != nil {
		t.Fatal("nil environment must normalize to empty")
	}
	for _, edit := range []func(*CodeCommand){func(r *CodeCommand) { r.Code = strings.Repeat("x", codeSourceLimit+1) }, func(r *CodeCommand) { r.Code = strings.Repeat("\n", codeSourceLimit) }, func(r *CodeCommand) { r.Environment = map[string]string{"BAD-NAME": "x"} }, func(r *CodeCommand) { r.Environment = map[string]string{"KEY": "x\x00"} }, func(r *CodeCommand) { r.Generation = 0 }, func(r *CodeCommand) { r.TimeoutMS = 300001 }} {
		copy := r
		edit(&copy)
		if copy.Validate() == nil {
			t.Fatal("invalid execution accepted", copy.Operation)
		}
	}
}
func TestCodeEventJSONPreservesFalseEmptyAndLargeJSONNumbers(t *testing.T) {
	for _, input := range []string{`{"type":"error","name":"Error","value":"","traceback":""}`, `{"type":"finished","status":"cancelled","context_usable":false}`, `{"type":"result","data":{"application/json":{"n":18446744073709551615}},"is_main_result":false}`} {
		var event CodeEvent
		if json.Unmarshal([]byte(input), &event) != nil {
			t.Fatal(input)
		}
		encoded, err := codeJSON(event)
		if err != nil {
			t.Fatal(err)
		}
		var before, after map[string]json.RawMessage
		_ = json.Unmarshal([]byte(input), &before)
		_ = json.Unmarshal(encoded, &after)
		if len(before) != len(after) {
			t.Fatal("empty required fields disappeared", string(encoded))
		}
		if event.Type == "result" && !strings.Contains(string(encoded), "18446744073709551615") {
			t.Fatal("numeric result lost precision", string(encoded))
		}
	}
	for _, input := range []string{`{"type":"started","data":null}`, `{"type":"stdout","data":"@@"}`, `{"type":"result","data":{"text/html":42},"is_main_result":false}`, `{"type":"finished","status":"running","context_usable":true}`} {
		var event CodeEvent
		if json.Unmarshal([]byte(input), &event) == nil {
			t.Fatal("invalid event accepted", input)
		}
	}
}
func TestCodeCompletedStatusDoesNotSkipRemainingEventPages(t *testing.T) {
	r := CodeCommand{Operation: "execution", ExecutionID: strings.Repeat("e", 24)}
	page := CodeExecutionPage{ID: r.ExecutionID, ContextID: strings.Repeat("c", 24), Generation: 1, Status: "completed", LastSequence: 3, NextSequence: 2,
		Events: []CodeSequencedEvent{{1, CodeEvent{Type: "started"}}, {2, CodeEvent{Type: "stdout", Data: json.RawMessage(`"eA=="`)}}}}
	if page.validate("", r) != nil {
		t.Fatal("completed status with remaining page rejected")
	}
	r.After = 2
	page.NextSequence = 3
	page.Events = []CodeSequencedEvent{{3, CodeEvent{Type: "finished", Status: "completed", ContextUsable: codeBool(true)}}}
	if page.validate("", r) != nil {
		t.Fatal("terminal page rejected")
	}
	page.Events[0].Event.Type = "started"
	if page.validate("", r) == nil {
		t.Fatal("bad terminal accepted")
	}
	page.Events = []CodeSequencedEvent{}
	page.NextSequence = 2
	if page.validate("", r) == nil {
		t.Fatal("empty non-evicted missing page accepted")
	}
	page.EventsEvicted = true
	if page.validate("", r) != nil {
		t.Fatal("explicit eviction rejected")
	}
}
func TestCodeCancellationBeforeSubmissionHasNoStartedEvent(t *testing.T) {
	r := CodeCommand{Operation: "execution", ExecutionID: strings.Repeat("e", 24)}
	p := CodeExecutionPage{ID: r.ExecutionID, ContextID: strings.Repeat("c", 24), Generation: 1, Status: "cancelled", Failure: codeText("cancelled_before_submit"), LastSequence: 1, NextSequence: 1,
		Events: []CodeSequencedEvent{{1, CodeEvent{Type: "finished", Status: "cancelled", ContextUsable: codeBool(true)}}}}
	if p.validate("", r) != nil {
		t.Fatal("pre-submission cancellation receipt rejected")
	}
	p.Failure = nil
	if p.validate("", r) == nil {
		t.Fatal("missing started event accepted for normal execution")
	}
	p.Failure = codeText("cancelled_before_submit")
	p.SessionID = "forged"
	if p.validate("", r) == nil {
		t.Fatal("guest session identity accepted")
	}
}
func TestCodeResponseRejectsCrossOperationAndMissingPayload(t *testing.T) {
	for _, input := range []string{`{"kind":"accepted","value":null}`, `{"kind":"contexts","value":null}`, `{"kind":"context","value":null}`, `{"kind":"accepted","extra":true}`} {
		var response CodeResponse
		err := json.Unmarshal([]byte(input), &response)
		if err == nil {
			err = response.validate("", CodeCommand{Operation: "list"})
		}
		if err == nil {
			t.Fatal(input)
		}
	}
}
