package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestInferenceLauncherResponsesKeepKnownIDAndNeverReplay(t *testing.T) {
	requireGuestProxyRoot(t)
	fixture, err := os.ReadFile("../../tests/fixtures/inference-sdk.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"valid", "lost", "nonce", "session", "task", "invoice", "meter", "missing-data", "both", "error-status", "error-id"} {
		t.Run(kind, func(t *testing.T) {
			var input struct {
				Result InferenceInvokeResult `json:"result"`
			}
			if json.Unmarshal(fixture, &input) != nil {
				t.Fatal("invalid fixture")
			}
			directory, err := os.MkdirTemp("", "infer-rpc-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(directory) })
			socket := filepath.Join(directory, "r.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			var connections atomic.Int32
			go func() {
				for {
					conn, err := listener.AcceptUnix()
					if err != nil {
						return
					}
					connections.Add(1)
					go func() {
						defer conn.Close()
						var request launcherInferenceRequest
						if json.NewDecoder(bufio.NewReader(conn)).Decode(&request) != nil || kind == "lost" {
							return
						}
						response := map[string]any{"protocol": launcherInferenceProtocol, "nonce": request.Nonce,
							"session_id": request.SessionID, "result": &input.Result}
						switch kind {
						case "nonce":
							response["nonce"] = strings.Repeat("e", 64)
						case "session":
							response["session_id"] = strings.Repeat("e", 24)
						case "task":
							input.Result.TaskID = strings.Repeat("e", 24)
						case "invoice":
							input.Result.Invocation.ID = strings.Repeat("e", 24)
						case "meter":
							input.Result.Invocation.SettledUnits = 0
						case "missing-data":
							data, _ := json.Marshal(input.Result)
							var result map[string]json.RawMessage
							_ = json.Unmarshal(data, &result)
							delete(result, "data")
							response["result"] = result
						case "both", "error-status", "error-id":
							response["error"] = &InferenceError{Code: "inference_replay", InvocationID: request.Invocation.ID}
							response["error_status"] = 409
							if kind != "both" {
								delete(response, "result")
							}
							if kind == "error-status" {
								response["error_status"] = 200
							}
							if kind == "error-id" {
								response["error"] = &InferenceError{Code: "inference_replay", InvocationID: strings.Repeat("e", 24)}
							}
						}
						_ = json.NewEncoder(conn).Encode(response)
					}()
				}
			}()
			// The expected IDs are captured before the simulated peer mutates its
			// reply; no response value can change the caller's query identity.
			taskID, invocationID := input.Result.TaskID, input.Result.Invocation.ID
			handle := &LauncherSessionClient{id: taskID, tenant: "tenant-a", socketPath: socket}
			request := InferenceInvokeRequest{ID: invocationID, Endpoint: "model", Payload: json.RawMessage(`{"query":"hi"}`)}
			result, err := handle.InvokeInference(context.Background(), request)
			if kind == "valid" {
				if err != nil || result.ValidateForTask(taskID, invocationID, "model") != nil {
					t.Fatal("valid root response rejected", err)
				}
			} else {
				code := "inference_protocol"
				if kind == "lost" {
					code = "inference_unavailable"
				}
				failure := expectInferenceFailure(t, err, code)
				if failure.InvocationID != invocationID {
					t.Fatal("bad response replaced known invocation ID")
				}
			}
			if connections.Load() != 1 {
				t.Fatal("root invocation was replayed", connections.Load())
			}
		})
	}
}
