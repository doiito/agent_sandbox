package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const linuxArtifactPort = 5005

type artifactReadCloser struct {
	io.Reader
	io.Closer
}

func (b FirecrackerLinuxBackend) exportSessionArtifact(ctx context.Context, request linuxArtifactRequest, workdir string) (*artifactBlob, error) {
	if !b.WorkspaceArtifacts {
		return nil, ErrArtifactsUnsupported
	}
	if !validSessionID(request.SessionID) || !validSessionID(request.ArtifactID) || !validSHA256Hex(request.Nonce) ||
		b.Pristine != (request.Binding != nil) || request.Binding != nil && (!request.Binding.valid() || request.Binding.SessionID != request.SessionID) {
		return nil, errors.New("invalid artifact identity or prepared binding")
	}
	if err := (SessionArtifactCreateRequest{Path: request.Path}).Validate(); err != nil {
		return nil, err
	}
	request.Protocol = linuxArtifactProtocol
	payload, err := json.Marshal(request)
	if err != nil || len(payload)+1 > 8192 {
		return nil, errArtifactProtocol
	}
	socket, err := b.vsockPath(workdir)
	if err != nil {
		return nil, err
	}
	transfer, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	handshake, stopHandshake := context.WithTimeout(transfer, 3*time.Second)
	defer stopHandshake()
	connection, reader, stop, err := dialFirecrackerVsock(handshake, socket, linuxArtifactPort)
	if err != nil {
		return nil, fmt.Errorf("%w: connect workspace artifact service", ErrUnavailable)
	}
	defer connection.Close()
	if !stop() || handshake.Err() != nil {
		return nil, fmt.Errorf("%w: workspace artifact handshake expired", ErrUnavailable)
	}
	deadline, _ := transfer.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("%w: set artifact deadline", ErrUnavailable)
	}
	stopTransfer := context.AfterFunc(transfer, func() { _ = connection.Close() })
	defer stopTransfer()
	if _, err := connection.Write(append(payload, '\n')); err != nil {
		return nil, fmt.Errorf("%w: send workspace artifact request", ErrUnavailable)
	}
	// CONNECT negotiation may already have buffered guest bytes.
	return buildSessionArtifact(transfer, workdir, request, artifactReadCloser{Reader: reader, Closer: connection})
}
