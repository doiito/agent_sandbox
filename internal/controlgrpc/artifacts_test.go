package controlgrpc

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	controlv1 "github.com/doiito/agent_sandbox/api/control/v1"
	"github.com/doiito/agent_sandbox/internal/sandbox"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestBridgeArtifactTypedCreateMaximumBinaryReadDeleteAndRange(t *testing.T) {
	aid := strings.Repeat("c", 24)
	data := bytes.Repeat([]byte{0, 255, 128, 42}, 128<<10)
	digest := sha256.Sum256(data)
	sum := hex.EncodeToString(digest[:])
	var creates, reads, deletes atomic.Int32
	_, conn, _ := bridgeForTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := "/v2/sessions/" + fixtureID + "/artifacts"
		switch {
		case r.Method == "POST" && r.URL.Path == path:
			creates.Add(1)
			var body sandbox.SessionArtifactCreateRequest
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Path != "/workspace" {
				t.Error("bad create conversion")
			}
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(sandbox.SessionArtifactInfo{ID: aid, SessionID: fixtureID, Path: body.Path, SourceKind: "directory", Format: "tar", Size: int64(len(data) + 4096), SHA256: sum, Entries: 1, Files: 1, PayloadBytes: int64(len(data))})
		case r.Method == "POST" && r.URL.Path == path+"/"+aid+"/read":
			reads.Add(1)
			var body sandbox.SessionArtifactReadRequest
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Error("bad read conversion")
			}
			if body.Offset > int64(len(data)+4096) {
				w.WriteHeader(416)
				_ = json.NewEncoder(w).Encode(sandbox.APIErrorResponse{Code: "artifact_range", Error: "invalid artifact range"})
				return
			}
			if body.Length != len(data) {
				t.Error("binary range changed", body.Length)
			}
			_ = json.NewEncoder(w).Encode(sandbox.SessionArtifactChunk{ID: aid, SessionID: fixtureID, Offset: body.Offset, TotalSize: int64(len(data) + 4096), DataBase64: base64.StdEncoding.EncodeToString(data), DataSHA256: sum, ArchiveSHA256: sum})
		case r.Method == "DELETE" && r.URL.Path == path+"/"+aid:
			deletes.Add(1)
			w.WriteHeader(204)
		default:
			t.Error("unexpected artifact route", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	client := controlv1.NewControlClient(conn)
	ctx, cancel := authContext(t)
	defer cancel()
	created, err := client.CreateSessionArtifact(ctx, &controlv1.CreateSessionArtifactRequest{Id: proto.String(fixtureID), Body: &controlv1.SessionArtifactCreateRequestInput{Path: proto.String("/workspace")}})
	if err != nil || created.GetId() != aid || created.GetSha256() != sum {
		t.Fatal(created, err)
	}
	request := &controlv1.ReadSessionArtifactRequest{Id: proto.String(fixtureID), Artifact: proto.String(aid), Body: &controlv1.SessionArtifactReadRequestInput{Offset: proto.Uint64(0), Length: proto.Uint64(uint64(len(data)))}}
	chunk, err := client.ReadSessionArtifact(ctx, request)
	if err != nil || !bytes.Equal(chunk.GetDataBase64(), data) || chunk.GetDataSha256() != sum || chunk.GetOffset() != 0 {
		t.Fatal("maximum protobuf binary chunk changed", err)
	}
	request.Body.Offset = proto.Uint64(uint64(len(data) + 8192))
	_, err = client.ReadSessionArtifact(ctx, request)
	if status.Code(err) != codes.OutOfRange {
		t.Fatal("range lost stable gRPC status", err)
	}
	if _, err := client.DeleteSessionArtifact(ctx, &controlv1.DeleteSessionArtifactRequest{Id: proto.String(fixtureID), Artifact: proto.String(aid)}); err != nil {
		t.Fatal(err)
	}
	if creates.Load() != 1 || reads.Load() != 2 || deletes.Load() != 1 {
		t.Fatal("artifact RPC replayed or skipped", creates.Load(), reads.Load(), deletes.Load())
	}
}
