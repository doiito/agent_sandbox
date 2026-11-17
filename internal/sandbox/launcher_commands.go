package sandbox

import (
	"context"
	"errors"
	"fmt"
	"time"
)

func (h *LauncherSessionClient) commandExchange(ctx context.Context, operation, id string, after int, request *SessionCommandRequest) (launcherSessionResponse, error) {
	return h.commandRPCExchange(ctx, launcherSessionRequest{Protocol: launcherSessionProtocol, Operation: operation, Tenant: h.tenant, SessionID: h.id, Command: request, CommandID: id, After: after})
}
func (h *LauncherSessionClient) commandRPCExchange(ctx context.Context, request launcherSessionRequest) (launcherSessionResponse, error) {
	var r launcherSessionResponse
	var err error
	for {
		r, err = h.exchange(ctx, request)
		if !errors.Is(err, ErrBusy) {
			break
		}
		select {
		case <-ctx.Done():
			return launcherSessionResponse{}, ErrBusy
		case <-time.After(5 * time.Millisecond):
		}
	}
	if err == nil && r.Error != "" {
		err = launcherSessionError(r)
	}
	return r, err
}
func (h *LauncherSessionClient) StartCommand(ctx context.Context, request SessionCommandRequest) (SessionCommandInfo, error) {
	r, err := h.commandExchange(ctx, "command-start", "", 0, &request)
	if err != nil {
		return SessionCommandInfo{}, err
	}
	if r.CommandInfo == nil || r.CommandInfo.SessionID != h.id || !validSessionID(r.CommandInfo.ID) {
		return SessionCommandInfo{}, fmt.Errorf("%w: invalid command start response", ErrUnavailable)
	}
	return *r.CommandInfo, nil
}
func (h *LauncherSessionClient) ListCommands(ctx context.Context) ([]SessionCommandInfo, error) {
	r, err := h.commandExchange(ctx, "command-list", "", 0, nil)
	if err != nil {
		return nil, err
	}
	if r.Commands == nil || len(*r.Commands) > commandHistoryLimit {
		return nil, fmt.Errorf("%w: invalid command list response", ErrUnavailable)
	}
	for _, info := range *r.Commands {
		if info.SessionID != h.id || !validSessionID(info.ID) {
			return nil, fmt.Errorf("%w: invalid command owner", ErrUnavailable)
		}
	}
	return *r.Commands, nil
}
func (h *LauncherSessionClient) PollCommand(ctx context.Context, id string, after int) (SessionCommandPage, error) {
	r, err := h.commandExchange(ctx, "command-poll", id, after, nil)
	if err != nil {
		return SessionCommandPage{}, err
	}
	if r.CommandPage == nil || r.CommandPage.Info.SessionID != h.id || r.CommandPage.Info.ID != id || r.CommandPage.NextSequence != after+len(r.CommandPage.Events) || len(r.CommandPage.Events) > 64 {
		return SessionCommandPage{}, fmt.Errorf("%w: invalid command page response", ErrUnavailable)
	}
	return *r.CommandPage, nil
}
func (h *LauncherSessionClient) CancelCommand(ctx context.Context, id string) (bool, error) {
	r, err := h.commandExchange(ctx, "command-kill", id, 0, nil)
	if err != nil {
		return false, err
	}
	if r.Killed == nil {
		return false, fmt.Errorf("%w: invalid command kill response", ErrUnavailable)
	}
	return *r.Killed, nil
}

func (s *Session) commandRPC(request launcherSessionRequest) launcherSessionResponse {
	r := launcherSessionResponse{Protocol: launcherSessionProtocol}
	var err error
	if request.File != nil || request.Input != nil && request.Operation != "command-stdin-submit" || request.InputSequence != 0 && request.Operation != "command-stdin-poll" {
		err = fmt.Errorf("command operation does not accept file data")
	} else {
		switch request.Operation {
		case "command-stdin-submit":
			if request.Input == nil || request.Command != nil || request.After != 0 {
				err = fmt.Errorf("invalid stdin submit")
				break
			}
			receipt, inputErr := s.SubmitCommandInput(request.CommandID, *request.Input)
			err = inputErr
			if err == nil {
				r.InputReceipt = &receipt
			}
		case "command-stdin-poll":
			if request.Command != nil || request.After != 0 {
				err = fmt.Errorf("invalid stdin poll")
				break
			}
			receipt, inputErr := s.PollCommandInput(request.CommandID, request.InputSequence)
			err = inputErr
			if err == nil {
				r.InputReceipt = &receipt
			}

		case "command-start":
			if request.Command == nil || request.CommandID != "" || request.After != 0 {
				err = fmt.Errorf("invalid command start")
				break
			}
			var info SessionCommandInfo
			info, err = s.StartCommand(*request.Command)
			if err == nil {
				r.CommandInfo = &info
			}
		case "command-list":
			if request.Command != nil || request.CommandID != "" || request.After != 0 {
				err = fmt.Errorf("invalid command list")
				break
			}
			list := s.ListCommands()
			r.Commands = &list
		case "command-poll":
			if request.Command != nil {
				err = fmt.Errorf("invalid command poll")
				break
			}
			var page SessionCommandPage
			page, err = s.PollCommand(request.CommandID, request.After)
			if err == nil {
				r.CommandPage = &page
			}
		case "command-kill":
			if request.Command != nil || request.After != 0 {
				err = fmt.Errorf("invalid command cancellation")
				break
			}
			var killed bool
			killed, err = s.CancelCommand(request.CommandID)
			if err == nil {
				r.Killed = &killed
			}
		default:
			err = fmt.Errorf("unsupported command operation")
		}
	}
	if err != nil {
		r.Error, r.Code = launcherSessionErrorFields(err)
	}
	return r
}
