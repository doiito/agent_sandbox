package sandbox

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	osvJobMagic         = "OSJ1"
	osvJobRequest       = 1
	osvJobResponse      = 2
	osvJobRequestMax    = 64 * 1024
	osvJobHeaderLen     = 48
	osvJobResultLen     = 64
	osvJobEnvMaxCount   = 32
	osvJobEnvMaxBytes   = 8192
	osvJobStdinMaxBytes = 16 * 1024
)

type osvJobResult struct {
	Status   int32
	ExitCode int32
	Stdout   []byte
	Stderr   []byte
	Flags    byte
}

func validOSvModulePath(path string) bool {
	if len(path) < 5 || len(path) >= 256 || path[0] != '/' || !strings.HasSuffix(path, ".so") {
		return false
	}
	for _, part := range strings.Split(path[1:], "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
		for _, ch := range part {
			if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
				(ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.') {
				return false
			}
		}
	}
	return true
}

// ValidOSvModulePath applies the same canonical guest path rule to template tools.
func ValidOSvModulePath(path string) bool { return validOSvModulePath(path) }

func canonicalJobID(id string) bool {
	if len(id) != 24 {
		return false
	}
	for _, ch := range id {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return false
		}
	}
	return true
}

func validateOSvEnvironment(environment map[string]string) ([]string, error) {
	if len(environment) > osvJobEnvMaxCount {
		return nil, errors.New("OSv environment exceeds 32 entries")
	}
	names := make([]string, 0, len(environment))
	total := 0
	for name, value := range environment {
		if len(name) < 1 || len(name) > 64 || len(value) > 1024 ||
			strings.HasPrefix(name, "LD_") || strings.HasPrefix(name, "OSV_") ||
			strings.IndexByte(value, 0) >= 0 {
			return nil, errors.New("invalid OSv environment name or value")
		}
		for index, char := range name {
			letter := char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z'
			if !letter && !(char == '_' || index > 0 && char >= '0' && char <= '9') {
				return nil, errors.New("invalid OSv environment name")
			}
		}
		total += len(name) + len(value)
		if total > osvJobEnvMaxBytes {
			return nil, errors.New("OSv environment exceeds 8192 bytes")
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func encodeOSvJobRequest(req RunRequest, nonce [16]byte, maxCapture int) ([]byte, error) {
	if !canonicalJobID(req.jobID) || !validOSvModulePath(req.Entrypoint) ||
		req.TimeoutMS < 1 || req.TimeoutMS > 300000 || maxCapture < 1 || maxCapture > 1<<20 || len(req.Args) > 64 {
		return nil, errors.New("invalid OSv job request")
	}
	envNames, err := validateOSvEnvironment(req.Environment)
	if err != nil {
		return nil, err
	}
	var body bytes.Buffer
	body.WriteString(osvJobMagic)
	flags := byte(0)
	if len(envNames) != 0 {
		flags = 1
	}
	if req.Stdin != nil {
		flags |= 2
	}
	body.Write([]byte{osvJobRequest, flags, 0, 0})
	body.WriteString(req.jobID)
	body.Write(nonce[:])
	_ = binary.Write(&body, binary.LittleEndian, uint32(req.TimeoutMS))
	_ = binary.Write(&body, binary.LittleEndian, uint32(maxCapture))
	_ = binary.Write(&body, binary.LittleEndian, uint16(len(req.Entrypoint)))
	_ = binary.Write(&body, binary.LittleEndian, uint16(len(req.Args)))
	body.WriteString(req.Entrypoint)
	// The guest module loader counts argv[0] (the signed module path).
	totalArgs := len(req.Entrypoint)
	for _, arg := range req.Args {
		if len(arg) > 4096 || strings.IndexByte(arg, 0) >= 0 {
			return nil, errors.New("invalid OSv job argument")
		}
		totalArgs += len(arg)
		if totalArgs > 32768 {
			return nil, errors.New("OSv job arguments exceed 32 KiB")
		}
		_ = binary.Write(&body, binary.LittleEndian, uint16(len(arg)))
		body.WriteString(arg)
	}
	if len(envNames) != 0 {
		_ = binary.Write(&body, binary.LittleEndian, uint16(len(envNames)))
		for _, name := range envNames {
			value := req.Environment[name]
			_ = binary.Write(&body, binary.LittleEndian, uint16(len(name)))
			_ = binary.Write(&body, binary.LittleEndian, uint16(len(value)))
			body.WriteString(name)
			body.WriteString(value)
		}
	}
	if req.Stdin != nil {
		if len(req.Stdin) > osvJobStdinMaxBytes {
			return nil, errors.New("OSv stdin exceeds 16 KiB")
		}
		_ = binary.Write(&body, binary.LittleEndian, uint16(len(req.Stdin)))
		body.Write(req.Stdin)
	}
	if body.Len() > osvJobRequestMax {
		return nil, errors.New("OSv job request exceeds 64 KiB")
	}
	frame := make([]byte, 4+body.Len())
	binary.LittleEndian.PutUint32(frame, uint32(body.Len()))
	copy(frame[4:], body.Bytes())
	return frame, nil
}

func decodeOSvJobResult(body []byte, id string, nonce [16]byte, maxCapture int) (osvJobResult, error) {
	var result osvJobResult
	if len(body) < osvJobResultLen || string(body[:4]) != osvJobMagic || body[4] != osvJobResponse ||
		body[5]&^byte(3) != 0 || body[6] != 0 || body[7] != 0 ||
		string(body[8:32]) != id || !bytes.Equal(body[32:48], nonce[:]) {
		return result, errors.New("invalid OSv job result header")
	}
	result.Flags = body[5]
	result.Status = int32(binary.LittleEndian.Uint32(body[48:52]))
	result.ExitCode = int32(binary.LittleEndian.Uint32(body[52:56]))
	stdoutLen := uint64(binary.LittleEndian.Uint32(body[56:60]))
	stderrLen := uint64(binary.LittleEndian.Uint32(body[60:64]))
	if stdoutLen+stderrLen > uint64(maxCapture) ||
		stdoutLen+stderrLen != uint64(len(body)-osvJobResultLen) ||
		result.Status > 0 || (result.Status != 0 && result.ExitCode != 0) {
		return osvJobResult{}, errors.New("invalid OSv job result length or status")
	}
	result.Stdout = body[64 : 64+stdoutLen]
	result.Stderr = body[64+stdoutLen:]
	return result, nil
}

func readOSvFrame(reader io.Reader, maxBody int) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return nil, err
	}
	length := binary.LittleEndian.Uint32(prefix[:])
	if length < osvJobResultLen || uint64(length) > uint64(maxBody) {
		return nil, fmt.Errorf("OSv frame length %d outside allowed range", length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	return body, nil
}
