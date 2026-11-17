package sandbox

import (
	"context"
	"fmt"
)

func (h *LauncherSessionClient) commandInputExchange(ctx context.Context, operation, id string, sequence int, input *SessionCommandInputRequest) (SessionCommandInputReceipt, error) {
	r, err := h.commandRPCExchange(ctx, launcherSessionRequest{Protocol: launcherSessionProtocol, Operation: operation, Tenant: h.tenant, SessionID: h.id, CommandID: id, Input: input, InputSequence: sequence})
	if err != nil {
		return SessionCommandInputReceipt{}, err
	}
	if r.InputReceipt == nil || r.InputReceipt.SessionID != h.id || r.InputReceipt.CommandID != id || r.InputReceipt.Sequence < 1 || r.InputReceipt.Sequence > commandInputRequestLimit || sequence != 0 && r.InputReceipt.Sequence != sequence {
		return SessionCommandInputReceipt{}, fmt.Errorf("%w: invalid stdin receipt binding", ErrUnavailable)
	}
	return *r.InputReceipt, nil
}
func (h *LauncherSessionClient) SubmitCommandInput(ctx context.Context, id string, input SessionCommandInputRequest) (SessionCommandInputReceipt, error) {
	return h.commandInputExchange(ctx, "command-stdin-submit", id, 0, &input)
}
func (h *LauncherSessionClient) PollCommandInput(ctx context.Context, id string, sequence int) (SessionCommandInputReceipt, error) {
	return h.commandInputExchange(ctx, "command-stdin-poll", id, sequence, nil)
}
