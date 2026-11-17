package mcp

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/doiito/agent_sandbox/internal/sandbox"
)

func (s *Server) callWatchTool(ctx context.Context, name string, args json.RawMessage, cap sandbox.CapabilityReport) outcome {
	if !cap.Features.FileWatch {
		return toolFailure("unsupported", "directory watching is unavailable for this session template")
	}
	var data json.RawMessage
	var err error
	if name == "sandbox.watch.start" {
		var request struct {
			sandbox.SessionWatchRequest
			SessionID string `json:"session_id"`
		}
		if decodeStrict(args, &request) != nil || request.SessionWatchRequest.Validate() != nil {
			return invalidArgs()
		}
		if request.Recursive && !cap.Features.RecursiveFileWatch || request.IncludeEntry && !cap.Features.FileWatchEntry {
			return toolFailure("unsupported", "requested watch options are unavailable")
		}
		path, e := sessionPath(request.SessionID)
		if e != nil {
			return invalidArgs()
		}
		data, err = s.api.call(ctx, "POST", path+"/watches", request.SessionWatchRequest)
		if err == nil {
			var info sandbox.SessionWatchInfo
			if json.Unmarshal(data, &info) != nil || !handlePattern.MatchString(info.ID) || info.SessionID != request.SessionID || info.Path != request.Path {
				return toolFailure("protocol_error", "invalid created watcher identity")
			}
			return outcome{Data: data, Rollback: s.api.rollback("DELETE", path+"/watches/"+info.ID)}
		}
	} else {
		var request struct {
			SessionID string `json:"session_id"`
			WatchID   string `json:"watch_id,omitempty"`
			After     int    `json:"after,omitempty"`
		}
		if decodeStrict(args, &request) != nil || request.After < 0 || request.After > 2147483647 {
			return invalidArgs()
		}
		path, e := sessionPath(request.SessionID)
		if e != nil {
			return invalidArgs()
		}
		path += "/watches"
		switch name {
		case "sandbox.watch.list":
			if request.WatchID != "" || request.After != 0 {
				return invalidArgs()
			}
			data, err = s.api.call(ctx, "GET", path, nil)
		case "sandbox.watch.poll":
			if !handlePattern.MatchString(request.WatchID) {
				return invalidArgs()
			}
			data, err = s.api.call(ctx, "GET", path+"/"+request.WatchID+"?after="+strconv.Itoa(request.After), nil)
		case "sandbox.watch.stop":
			if !handlePattern.MatchString(request.WatchID) || request.After != 0 {
				return invalidArgs()
			}
			data, err = s.api.call(ctx, "DELETE", path+"/"+request.WatchID, nil)
		default:
			return invalidArgs()
		}
	}
	if err != nil {
		return failure(err)
	}
	return outcome{Data: data}
}
