package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	osvPristineMagic        = "OSP1"
	osvPristineInputsMagic  = "OSP2"
	osvPristinePing         = 1
	osvPristinePrepare      = 3
	osvPristineRequestLen   = 52
	osvPristineResponseLen  = 64
	osvPristineInputsMaxLen = osvPristineRequestLen + 4 + 64*8 + 32*1024 + 512*1024
)

type osvPristineBinding struct {
	ID    string
	Nonce [16]byte
}

type osvPristineRequest struct {
	Operation  byte
	Binding    osvPristineBinding
	TTLMS      int
	InputsV1   bool
	InputFiles []InputFile
}

func newOSvPristineBinding(id string) (osvPristineBinding, error) {
	if !canonicalJobID(id) {
		return osvPristineBinding{}, errors.New("invalid OSv pristine ID")
	}
	value := osvPristineBinding{ID: id}
	if _, err := rand.Read(value.Nonce[:]); err != nil {
		return osvPristineBinding{}, err
	}
	if value.Nonce == [16]byte{} {
		return osvPristineBinding{}, errors.New("empty OSv pristine nonce")
	}
	return value, nil
}

func validateOSvPristineRequest(request osvPristineRequest) (int, error) {
	if !canonicalJobID(request.Binding.ID) || request.Binding.Nonce == [16]byte{} ||
		(request.Operation != osvPristinePing && request.Operation != osvPristinePrepare) ||
		(request.Operation == osvPristinePing && request.TTLMS != 0) ||
		(request.Operation == osvPristinePrepare && (request.TTLMS < 1000 || request.TTLMS > 300000)) {
		return 0, errors.New("invalid OSv pristine control request")
	}
	if len(request.InputFiles) != 0 && (!request.InputsV1 || request.Operation != osvPristinePrepare) {
		return 0, errors.New("OSv input files require OSP2 preparation")
	}
	if err := validateInputFiles(request.InputFiles); err != nil {
		return 0, err
	}
	size := osvPristineRequestLen
	if request.InputsV1 && request.Operation == osvPristinePrepare {
		size += 4
		for _, input := range request.InputFiles {
			size += 8 + len(input.Path) + len(input.Data)
		}
	}
	if size > osvPristineInputsMaxLen {
		return 0, errors.New("OSv input preparation frame exceeds bound")
	}
	return size, nil
}

func osvPristineWireIdentity(inputs bool) (string, uint32) {
	if inputs {
		return osvPristineInputsMagic, 2
	}
	return osvPristineMagic, 1
}

func encodeOSvPristineRequest(request osvPristineRequest) ([]byte, error) {
	size, err := validateOSvPristineRequest(request)
	if err != nil {
		return nil, err
	}
	frame := make([]byte, 4+size)
	binary.LittleEndian.PutUint32(frame, uint32(size))
	body := frame[4:]
	magic, _ := osvPristineWireIdentity(request.InputsV1)
	copy(body, magic)
	body[4] = request.Operation
	copy(body[8:32], request.Binding.ID)
	copy(body[32:48], request.Binding.Nonce[:])
	binary.LittleEndian.PutUint32(body[48:], uint32(request.TTLMS))
	if request.InputsV1 && request.Operation == osvPristinePrepare {
		binary.LittleEndian.PutUint16(body[52:54], uint16(len(request.InputFiles)))
		cursor := 56
		for _, input := range request.InputFiles {
			binary.LittleEndian.PutUint16(body[cursor:cursor+2], uint16(len(input.Path)))
			binary.LittleEndian.PutUint32(body[cursor+4:cursor+8], uint32(len(input.Data)))
			cursor += 8
			cursor += copy(body[cursor:], input.Path)
			cursor += copy(body[cursor:], input.Data)
		}
	}
	return frame, nil
}

func decodeOSvPristineResponse(body []byte, request osvPristineRequest) (time.Duration, error) {
	if _, err := validateOSvPristineRequest(request); err != nil {
		return 0, err
	}
	magic, revision := osvPristineWireIdentity(request.InputsV1)
	if len(body) != osvPristineResponseLen || string(body[:4]) != magic ||
		body[4] != request.Operation+1 || body[5] != 0 || body[6] != 0 || body[7] != 0 ||
		string(body[8:32]) != request.Binding.ID || !bytes.Equal(body[32:48], request.Binding.Nonce[:]) ||
		binary.LittleEndian.Uint32(body[48:52]) != revision || binary.LittleEndian.Uint32(body[60:64]) != 0 {
		return 0, errors.New("invalid OSv pristine response binding, revision or status")
	}
	state, maxRemaining := uint32(0), uint32(600000)
	if request.Operation == osvPristinePrepare {
		state, maxRemaining = 1, uint32(request.TTLMS)
	}
	remaining := binary.LittleEndian.Uint32(body[56:60])
	if binary.LittleEndian.Uint32(body[52:56]) != state || remaining == 0 || remaining > maxRemaining {
		return 0, errors.New("invalid OSv pristine state or remaining lifetime")
	}
	return time.Duration(remaining) * time.Millisecond, nil
}

func (b FirecrackerOSvBackend) probePristine(ctx context.Context, workdir string) (time.Duration, error) {
	id, err := randomID()
	if err != nil {
		return 0, err
	}
	binding, err := newOSvPristineBinding(id)
	if err != nil {
		return 0, err
	}
	return b.exchangePristine(ctx, osvPristineRequest{Operation: osvPristinePing, Binding: binding, InputsV1: b.ReadonlyInputs}, workdir)
}

func (b FirecrackerOSvBackend) preparePristine(ctx context.Context, binding osvPristineBinding, ttlMS int, workdir string) error {
	return b.preparePristineInputs(ctx, binding, ttlMS, nil, workdir)
}

func (b FirecrackerOSvBackend) preparePristineInputs(ctx context.Context, binding osvPristineBinding, ttlMS int, files []InputFile, workdir string) error {
	_, err := b.exchangePristine(ctx, osvPristineRequest{Operation: osvPristinePrepare, Binding: binding, TTLMS: ttlMS,
		InputsV1: b.ReadonlyInputs, InputFiles: files}, workdir)
	return err
}

// A control payload is sent once. A lost prepared ACK cannot be retried.
func (b FirecrackerOSvBackend) exchangePristine(ctx context.Context, request osvPristineRequest, workdir string) (time.Duration, error) {
	if !b.Pristine {
		return 0, errors.New("OSv pristine exchange requires explicit boot mode")
	}
	frame, err := encodeOSvPristineRequest(request)
	if err != nil {
		return 0, err
	}
	socketPath, err := jailedFirecrackerVsockPath(b.Path, workdir)
	if err != nil {
		if request.Operation == osvPristinePrepare {
			err = errors.Join(errPristinePrepareNotSent, err)
		}
		return 0, err
	}
	conn, reader, stopClosing, err := dialFirecrackerVsock(ctx, socketPath, osvJobPort)
	if err != nil {
		if request.Operation == osvPristinePrepare {
			err = errors.Join(errPristinePrepareNotSent, err)
		}
		return 0, err
	}
	defer stopClosing()
	defer conn.Close()
	if _, err := io.Copy(conn, bytes.NewReader(frame)); err != nil {
		return 0, fmt.Errorf("write OSv pristine control: %w", err)
	}
	body, err := readOSvFrame(reader, osvPristineResponseLen)
	if err != nil {
		return 0, fmt.Errorf("read OSv pristine response: %w", err)
	}
	remaining, err := decodeOSvPristineResponse(body, request)
	if err != nil {
		return 0, err
	}
	if _, err := conn.Write([]byte{0xa5}); err != nil {
		return 0, fmt.Errorf("acknowledge OSv pristine response: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		if err == nil {
			return 0, errors.New("OSv pristine control has bytes after response")
		}
		return 0, fmt.Errorf("OSv pristine control missing terminal EOF: %w", err)
	}
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	return remaining, nil
}

func (b FirecrackerOSvBackend) exchangePrepared(ctx context.Context, request RunRequest, binding osvPristineBinding, workdir string) (string, error) {
	if !b.Pristine || request.jobID != binding.ID || binding.Nonce == [16]byte{} {
		return "", errors.New("OSv prepared execution requires matching binding and boot mode")
	}
	return b.exchangeJob(ctx, request, workdir, binding.Nonce)
}
