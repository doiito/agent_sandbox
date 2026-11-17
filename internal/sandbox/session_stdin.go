package sandbox

import (
	"encoding/base64"
	"errors"
	"fmt"
)

const commandInputChunkLimit = 16 * 1024
const commandInputByteLimit = 1024 * 1024
const commandInputRequestLimit = 256

var ErrStdinClosed = errors.New("command stdin is closed")
var ErrStdinUnavailable = errors.New("command was started without interactive stdin")
var ErrStdinLimit = errors.New("command stdin limit exceeded")

type SessionCommandInputRequest struct {
	DataBase64 string `json:"data_base64"`
	Close      bool   `json:"close"`
}

func (r SessionCommandInputRequest) data() ([]byte, error) {
	if len(r.DataBase64) > (commandInputChunkLimit+2)/3*4 {
		return nil, ErrStdinLimit
	}
	data, err := base64.StdEncoding.Strict().DecodeString(r.DataBase64)
	if err != nil || base64.StdEncoding.EncodeToString(data) != r.DataBase64 || r.Close && len(data) != 0 {
		return nil, fmt.Errorf("invalid command stdin data or close")
	}
	if len(data) > commandInputChunkLimit {
		return nil, ErrStdinLimit
	}
	return data, nil
}

type SessionCommandInputReceipt struct {
	SessionID    string `json:"session_id"`
	CommandID    string `json:"command_id"`
	Sequence     int    `json:"sequence"`
	State        string `json:"state"`
	WrittenBytes int    `json:"written_bytes"`
	Closed       bool   `json:"closed"`
	ErrorCode    string `json:"error_code,omitempty"`
}
type linuxCommandInput struct {
	Protocol   string             `json:"protocol"`
	JobID      string             `json:"job_id"`
	Binding    *linuxGuestBinding `json:"binding,omitempty"`
	Sequence   int                `json:"sequence"`
	DataBase64 string             `json:"data_base64"`
	Close      bool               `json:"close"`
}
type linuxCommandInputAck struct {
	Protocol     string             `json:"protocol"`
	JobID        string             `json:"job_id"`
	Binding      *linuxGuestBinding `json:"binding,omitempty"`
	Sequence     int                `json:"sequence"`
	WrittenBytes int                `json:"written_bytes"`
	Closed       bool               `json:"closed"`
	ErrorCode    *string            `json:"error_code"`
}

func (s *Session) SubmitCommandInput(id string, request SessionCommandInputRequest) (SessionCommandInputReceipt, error) {
	data, err := request.data()
	if err != nil {
		return SessionCommandInputReceipt{}, err
	}
	r, err := s.command(id)
	if err != nil {
		return SessionCommandInputReceipt{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.finished || r.cancelled || s.closed.Load() {
		return SessionCommandInputReceipt{}, ErrCommandNotFound
	}
	if !r.info.InteractiveStdin {
		return SessionCommandInputReceipt{}, ErrStdinUnavailable
	}
	if r.inputPending != 0 {
		return SessionCommandInputReceipt{}, ErrBusy
	}
	if r.info.StdinClosed && !request.Close {
		return SessionCommandInputReceipt{}, ErrStdinClosed
	}
	if len(r.inputReceipts) >= commandInputRequestLimit || r.inputBytes+len(data) > commandInputByteLimit {
		return SessionCommandInputReceipt{}, ErrStdinLimit
	}
	seq := len(r.inputReceipts) + 1
	receipt := SessionCommandInputReceipt{SessionID: s.info.ID, CommandID: id, Sequence: seq, State: "pending"}
	if r.info.StdinClosed && request.Close {
		receipt.State = "closed"
		receipt.Closed = true
	} else {
		// Reserve before publishing so a guest ack can never race receipt creation.
		r.inputPending = seq
	}
	r.inputReceipts = append(r.inputReceipts, receipt)
	r.inputBytes += len(data)
	if r.inputPending != 0 {
		r.input <- linuxCommandInput{Sequence: seq, DataBase64: request.DataBase64, Close: request.Close}
	}
	return receipt, nil
}
func (s *Session) PollCommandInput(id string, sequence int) (SessionCommandInputReceipt, error) {
	r, err := s.command(id)
	if err != nil {
		return SessionCommandInputReceipt{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if sequence <= 0 || sequence > len(r.inputReceipts) {
		return SessionCommandInputReceipt{}, ErrCommandNotFound
	}
	return r.inputReceipts[sequence-1], nil
}
func (r *commandRecord) acknowledgeInput(ack linuxCommandInputAck) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ack.Sequence != r.inputPending || ack.Sequence <= 0 || ack.Sequence > len(r.inputReceipts) {
		return errors.New("unexpected stdin acknowledgement")
	}
	receipt := &r.inputReceipts[ack.Sequence-1]
	receipt.WrittenBytes = ack.WrittenBytes
	receipt.Closed = ack.Closed
	receipt.State = "delivered"
	if ack.Closed {
		r.info.StdinClosed = true
		receipt.State = "closed"
	}
	if ack.ErrorCode != nil {
		receipt.State = "failed"
		receipt.ErrorCode = *ack.ErrorCode
	}
	r.inputPending = 0
	return nil
}
func (r *commandRecord) finishInput() {
	select {
	case <-r.input:
	default:
	}
	if r.inputPending != 0 {
		receipt := &r.inputReceipts[r.inputPending-1]
		receipt.State = "failed"
		receipt.ErrorCode = "command_exited"
		receipt.Closed = true
		r.inputPending = 0
	}
	r.info.StdinClosed = true
}
