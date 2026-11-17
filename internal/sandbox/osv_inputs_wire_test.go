package sandbox

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestOSvInputWireMatchesActualGuestTransactionVector(t *testing.T) {
	data, err := os.ReadFile("../../tests/fixtures/osv-pristine-inputs-wire-v1.txt")
	if err != nil {
		t.Fatal(err)
	}
	rows := strings.Fields(string(data))
	if len(rows) != 2 {
		t.Fatal("invalid shared OSP2 fixture")
	}
	expected, err := hex.DecodeString(rows[0])
	if err != nil {
		t.Fatal(err)
	}
	response, err := hex.DecodeString(rows[1])
	if err != nil {
		t.Fatal(err)
	}
	request := inputPreparation(t)
	request.InputFiles = []InputFile{{Path: "x", Data: []byte{'A', 0, 255, '\n'}}}
	frame, err := encodeOSvPristineRequest(request)
	if err != nil || !bytes.Equal(frame[4:], expected) {
		t.Fatalf("Go/C OSP2 preparation differs: %x %v", frame, err)
	}
	remaining, err := decodeOSvPristineResponse(response, request)
	if err != nil || remaining != 993*time.Millisecond {
		t.Fatal("actual guest response differs", remaining, err)
	}
}

func inputPreparation(t *testing.T) osvPristineRequest {
	t.Helper()
	request, _, _ := pristineVector(t)
	request.Operation, request.TTLMS, request.InputsV1 = osvPristinePrepare, 1000, true
	return request
}

func TestOSvInputPreparationUsesExplicitOSP2AndPreservesBinaryData(t *testing.T) {
	request := inputPreparation(t)
	request.InputFiles = []InputFile{{Path: "nested/data", Data: []byte{'A', 0, 0xff, '\n'}}}
	frame, err := encodeOSvPristineRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	body := frame[4:]
	if string(body[:4]) != "OSP2" || binary.LittleEndian.Uint32(frame) != uint32(len(body)) ||
		binary.LittleEndian.Uint16(body[52:54]) != 1 || binary.LittleEndian.Uint16(body[54:56]) != 0 ||
		binary.LittleEndian.Uint16(body[56:58]) != 11 || binary.LittleEndian.Uint16(body[58:60]) != 0 ||
		binary.LittleEndian.Uint32(body[60:64]) != 4 || string(body[64:75]) != "nested/data" ||
		!bytes.Equal(body[75:], request.InputFiles[0].Data) {
		t.Fatalf("OSP2 input encoding lost its shape or bytes: %x", frame)
	}
	request.InputFiles = nil
	empty, err := encodeOSvPristineRequest(request)
	if err != nil || len(empty) != 4+56 || !bytes.Equal(empty[len(empty)-4:], make([]byte, 4)) {
		t.Fatalf("empty OSP2 preparation must still carry an input count: %x %v", empty, err)
	}
	request.InputsV1 = false
	legacy, err := encodeOSvPristineRequest(request)
	if err != nil || len(legacy) != 4+52 || string(legacy[4:8]) != "OSP1" {
		t.Fatalf("OSP1 preparation changed: %x %v", legacy, err)
	}
}

func TestOSvInputPreparationMaximumShapeAndPublicValidation(t *testing.T) {
	request := inputPreparation(t)
	for i := range 64 {
		path := strings.Repeat("a", 250) + "/" + strings.Repeat("b", 250) + "/" + fmt.Sprintf("%010d", i)
		request.InputFiles = append(request.InputFiles, InputFile{Path: path, Data: bytes.Repeat([]byte{0xff}, 8192)})
	}
	frame, err := encodeOSvPristineRequest(request)
	if err != nil || len(frame) != 4+557624 {
		t.Fatalf("exact simultaneous input limits rejected: size=%d error=%v", len(frame), err)
	}
	for name, files := range map[string][]InputFile{
		"count":      append(append([]InputFile{}, request.InputFiles...), InputFile{Path: "extra"}),
		"data":       {{Path: "x", Data: make([]byte, 512*1024+1)}},
		"path total": append(append([]InputFile{}, request.InputFiles[:63]...), InputFile{Path: request.InputFiles[63].Path + "x"}),
		"traversal":  {{Path: "a/../b"}},
		"duplicate":  {{Path: "a"}, {Path: "a"}},
		"parent":     {{Path: "a/b"}, {Path: "a"}},
		"utf8":       {{Path: string([]byte{0xff})}},
		"control":    {{Path: "a\u0085b"}},
		"executable": {{Path: "x", Mode: 0o555}},
	} {
		t.Run(name, func(t *testing.T) {
			invalid := inputPreparation(t)
			invalid.InputFiles = files
			if _, err := encodeOSvPristineRequest(invalid); err == nil {
				t.Fatal("invalid input shape accepted")
			}
		})
	}
}

func TestOSvInputProtocolCannotBeUsedAsLegacyOrPingPayload(t *testing.T) {
	request := inputPreparation(t)
	request.InputFiles = []InputFile{{Path: "x", Data: []byte("data")}}
	request.InputsV1 = false
	if _, err := encodeOSvPristineRequest(request); err == nil {
		t.Fatal("legacy preparation accepted inputs")
	}
	request.InputsV1, request.Operation, request.TTLMS = true, osvPristinePing, 0
	if _, err := encodeOSvPristineRequest(request); err == nil {
		t.Fatal("pristine ping accepted tenant inputs")
	}
	request.InputFiles = nil
	frame, err := encodeOSvPristineRequest(request)
	if err != nil || len(frame) != 4+52 || string(frame[4:8]) != "OSP2" {
		t.Fatalf("OSP2 ping shape changed: %x %v", frame, err)
	}
}

func TestOSvInputResponseRequiresItsActualRevisionAndBinding(t *testing.T) {
	request := inputPreparation(t)
	_, _, response := pristineVector(t)
	copy(response, "OSP2")
	response[4] = osvPristinePrepare + 1
	binary.LittleEndian.PutUint32(response[48:52], 2)
	binary.LittleEndian.PutUint32(response[52:56], 1)
	binary.LittleEndian.PutUint32(response[56:60], 995)
	remaining, err := decodeOSvPristineResponse(response, request)
	if err != nil || remaining != 995*time.Millisecond {
		t.Fatalf("valid OSP2 response rejected: %v %v", remaining, err)
	}
	for _, offset := range []int{0, 4, 8, 32, 48, 52, 60} {
		invalid := bytes.Clone(response)
		invalid[offset] ^= 1
		if _, err := decodeOSvPristineResponse(invalid, request); err == nil {
			t.Fatalf("corrupt response byte %d accepted", offset)
		}
	}
	request.InputsV1 = false
	if _, err := decodeOSvPristineResponse(response, request); err == nil {
		t.Fatal("OSP1 request accepted OSP2 response")
	}
}
