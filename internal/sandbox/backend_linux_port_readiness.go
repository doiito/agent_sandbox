package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
)

type linuxPortReadiness struct {
	Revision       int    `json:"revision"`
	Protocol       string `json:"protocol"`
	Port           int    `json:"port"`
	Target         string `json:"target"`
	State          string `json:"state"`
	MaxConnections int    `json:"max_connections"`
	MaxRecords     int    `json:"max_records"`
	MaxFrameBytes  int    `json:"max_frame_bytes"`
	MaxBytes       uint64 `json:"max_bytes"`
	MaxDurationMS  uint64 `json:"max_duration_ms"`
}

func (b FirecrackerLinuxBackend) validatePortReadiness(request linuxJobRequest, result json.RawMessage) error {
	if !b.PortForward || (request.Operation != "ping" && request.Operation != "prepare") {
		return nil
	}
	var envelope struct {
		OK    bool            `json:"ok"`
		Ports json.RawMessage `json:"port_service"`
	}
	if json.Unmarshal(result, &envelope) != nil {
		return errPortProtocol
	}
	if !envelope.OK {
		return nil
	}
	if request.Prepare != nil && request.Prepare.Mode == "job" {
		if len(envelope.Ports) > 0 && !bytes.Equal(bytes.TrimSpace(envelope.Ports), []byte("null")) {
			return errors.New("one-shot guest incorrectly advertised port authorization")
		}
		return nil
	}
	state := "session"
	if b.Pristine && request.Prepare == nil && request.Binding == nil {
		state = "pending"
	}
	var proof linuxPortReadiness
	if codeDecode(envelope.Ports, &proof) != nil || proof.Revision != 1 || proof.Protocol != linuxPortProtocol || proof.Port != linuxPortServicePort || proof.Target != "ipv4_loopback" || proof.State != state ||
		proof.MaxConnections != sessionPortActiveLimit || proof.MaxRecords != sessionPortHistoryLimit || proof.MaxFrameBytes != portDataLimit || proof.MaxBytes != portByteLimit || proof.MaxDurationMS != portDurationLimitMS {
		return errors.New("guest did not prove signed port service readiness and authorization state")
	}
	return nil
}
