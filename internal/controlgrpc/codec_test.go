package controlgrpc

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	controlv1 "github.com/doiito/agent_sandbox/api/control/v1"
	"github.com/doiito/agent_sandbox/internal/sandbox"
	"google.golang.org/protobuf/proto"
)

func codecForTest(t *testing.T) *wireCodec {
	t.Helper()
	codec, err := newWireCodec()
	if err != nil {
		t.Fatal(err)
	}
	return codec
}

func valueForTest(t *testing.T, data []byte) any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestCodecActualGoWireSamplesSurviveProtobuf(t *testing.T) {
	codec := codecForTest(t)
	data, err := os.ReadFile("testdata/actual-rest-encoder-samples.json")
	if err != nil {
		t.Fatal(err)
	}
	var samples []struct {
		Schema string          `json:"schema"`
		Value  json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(data, &samples); err != nil || len(samples) != 43 {
		t.Fatalf("expected the 43 original encoder samples: %v", err)
	}
	inputs := map[string]any{
		"RunRequestInput": sandbox.RunRequest{}, "RunRequestV2Input": sandbox.RunRequest{},
		"SessionCreateRequestInput": sandbox.SessionCreateRequest{}, "SessionCommandRequestInput": sandbox.SessionCommandRequest{},
		"SessionTimeoutRequestInput": sandbox.SessionTimeoutRequest{}, "PreviewCreateRequestInput": sandbox.PreviewCreateRequest{},
		"CodeContextCreateRequestInput": sandbox.CodeContextCreateRequest{}, "CodeContextDefaultRequestInput": sandbox.CodeContextDefaultRequest{},
		"CodeContextRestartRequestInput": sandbox.CodeContextRestartRequest{}, "CodeExecutionRequestInput": sandbox.CodeExecutionRequest{},
		"SessionCommandInputRequestInput": sandbox.SessionCommandInputRequest{}, "SessionWatchRequestInput": sandbox.SessionWatchRequest{},
		"SessionFileRequestInput": sandbox.SessionFileRequest{}, "NetworkFetchRequestInput": sandbox.NetworkFetchRequest{},
		"SessionPortLimitsInput": sandbox.SessionPortLimits{}, "InferenceInvokeRequestInput": sandbox.InferenceInvokeRequest{},
	}
	for index, sample := range samples {
		t.Run(sample.Schema+"/"+string(rune('A'+index)), func(t *testing.T) {
			message, err := codec.fromJSON(sample.Schema, sample.Value)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := proto.Marshal(message)
			if err != nil {
				t.Fatal(err)
			}
			received := codec.newMessage(sample.Schema)
			if err := proto.Unmarshal(wire, received); err != nil {
				t.Fatal(err)
			}
			after, err := codec.toJSON(received)
			if err != nil {
				t.Fatal(err)
			}
			if model, exists := inputs[sample.Schema]; exists {
				beforeGo, afterGo := reflect.New(reflect.TypeOf(model)).Interface(), reflect.New(reflect.TypeOf(model)).Interface()
				if err := json.Unmarshal(sample.Value, beforeGo); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(after, afterGo); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(beforeGo, afterGo) {
					t.Fatalf("protobuf changed actual Go input semantics: %s -> %s", sample.Value, after)
				}
			} else if !reflect.DeepEqual(valueForTest(t, sample.Value), valueForTest(t, after)) {
				t.Fatalf("protobuf changed actual JSON response values: %s -> %s", sample.Value, after)
			}
		})
	}
}

func TestCodecExactDynamicJSONAndEmptyCollectionPresence(t *testing.T) {
	codec := codecForTest(t)
	for _, data := range []string{
		`{"large":18446744073709551615,"exponent":1e400,"fraction":1.0000,"negative":-0,"nil":null,"array":[],"map":{},"false":false,"empty":""}`,
		`[null,false,"",[],{},9007199254740993]`,
	} {
		message, err := codec.fromJSON("JsonValue", []byte(data))
		if err != nil {
			t.Fatal(err)
		}
		wire, err := proto.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		received := &controlv1.JsonValue{}
		if err := proto.Unmarshal(wire, received); err != nil {
			t.Fatal(err)
		}
		after, err := codec.toJSON(received)
		if err != nil || !reflect.DeepEqual(valueForTest(t, []byte(data)), valueForTest(t, after)) {
			t.Fatalf("dynamic JSON precision/presence changed: %v: %s", err, after)
		}
	}
	for _, data := range []string{`{}`, `{"args":null}`, `{"args":[]}`, `{"environment":{}}`} {
		message, err := codec.fromJSON("RunRequestInput", []byte(data))
		if err != nil {
			t.Fatal(err)
		}
		after, err := codec.toJSON(message)
		if err != nil {
			t.Fatal(err)
		}
		var beforeGo, afterGo sandbox.RunRequest
		if err := json.Unmarshal([]byte(data), &beforeGo); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(after, &afterGo); err != nil || !reflect.DeepEqual(beforeGo, afterGo) {
			t.Fatalf("empty/absent collection changed: %s -> %s (%v)", data, after, err)
		}
	}
}

func TestCodecRejectsLossyOrMalformedTypedValues(t *testing.T) {
	codec := codecForTest(t)
	for _, example := range []struct{ name, data string }{
		{"SessionFileRequestInput", `{"action":"write","path":"/workspace/a","data_base64":"YQ==\n"}`},
		{"CodeEventOutput", `{"type":"finished","status":"completed"}`},
		{"CodeEventOutput", `{"type":"unknown"}`},
		{"CodeContextDefaultRequestInput", `{"unknown":"private-sentinel"}`},
		{"JsonValue", `true false`},
	} {
		if _, err := codec.fromJSON(example.name, []byte(example.data)); err == nil || strings.Contains(err.Error(), "private-sentinel") {
			t.Fatalf("malformed/lossy input accepted or error leaked data: %s", example.name)
		}
	}
	for _, value := range []*controlv1.JsonValue{
		{}, {Kind: &controlv1.JsonValue_Number{Number: "NaN"}}, {Kind: &controlv1.JsonValue_Number{Number: "01"}},
	} {
		if _, err := codec.toJSON(value); err == nil {
			t.Fatal("invalid native JSON value accepted")
		}
	}
	// Keep a complete real Go bill so rejection is caused by the changed unit
	// value, rather than by unrelated missing required response fields.
	data, err := json.Marshal(sandbox.InferenceBill{Protocol: "osv-sandbox-inference-bill/v1", Tenant: "tenant-a",
		TaskID: fixtureID, VMID: fixtureID, LeaseID: fixtureID, Unit: "units", HeldUnits: sandbox.InferenceUnits(^uint64(0))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.fromJSON("InferenceBillOutput", data); err != nil {
		t.Fatal(err)
	}
	var bill map[string]json.RawMessage
	if err := json.Unmarshal(data, &bill); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{`"18446744073709551616"`, `"01"`} {
		bill["held_units"] = json.RawMessage(invalid)
		changed, err := json.Marshal(bill)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := codec.fromJSON("InferenceBillOutput", changed); err == nil {
			t.Fatal("overflow/noncanonical billing units accepted")
		}
	}
}
