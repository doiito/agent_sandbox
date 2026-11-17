package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// HTTPPortError deliberately excludes server error text and control credentials.
type HTTPPortError struct {
	Status int
	Code   string
}

func (e *HTTPPortError) Error() string {
	return fmt.Sprintf("port open rejected (%d %s)", e.Status, e.Code)
}

// ValidateFor checks a strictly decoded control response against its known ID.
func (i SessionPortInfo) ValidateFor(id string, port uint16, maximum uint64) error {
	return i.validate(id, port, maximum)
}

type PortTunnelFrame struct {
	Kind string
	Data []byte
	Info *SessionPortInfo
}
type HTTPPortTunnel struct{ stream *linuxPortStream }

func (t *HTTPPortTunnel) Close() { t.stream.Close() }
func (t *HTTPPortTunnel) Write(data []byte) (int, error) {
	if len(data) < 1 || len(data) > portDataLimit {
		return 0, &PortRequestError{Code: "invalid_request"}
	}
	return t.stream.Write(data)
}
func (t *HTTPPortTunnel) CloseWrite() error { return t.stream.CloseWrite() }
func (t *HTTPPortTunnel) Next() (PortTunnelFrame, error) {
	f, err := t.stream.Next()
	frame := PortTunnelFrame{Data: f.Data, Info: f.Info}
	switch f.Kind {
	case portDataFrame:
		frame.Kind = "data"
	case portEOFFrame:
		frame.Kind = "eof"
	case portFinishedFrame:
		frame.Kind = "finished"
	}
	return frame, err
}

// OpenHTTPPortTunnel attempts admission once, retaining request.ID on every
// outcome. start only owns negotiation; lifetime owns the upgraded transport.
// There is no output queue and no automatic POST or DATA retry.
func OpenHTTPPortTunnel(start, lifetime context.Context, client *http.Client, origin, token, sid string, request SessionPortRequest) (*HTTPPortTunnel, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		client == nil || !validSessionID(sid) || !validSessionID(request.ID) || request.Port == 0 || !request.Limits.valid() || token == "" || strings.ContainsAny(token, "\r\n\x00") {
		return nil, &PortRequestError{Code: "invalid_request"}
	}
	bounded, cancel := context.WithTimeout(lifetime, time.Duration(request.Limits.TimeoutMS)*time.Millisecond)
	success := false
	defer func() {
		if !success {
			cancel()
		}
	}()
	startupTimeout := 10 * time.Second
	if client.Timeout > 0 && client.Timeout < startupTimeout {
		startupTimeout = client.Timeout
	}
	startup, stopStartup := context.WithTimeout(start, startupTimeout)
	defer stopStartup()
	stopStart := context.AfterFunc(startup, cancel)
	defer stopStart()
	body, _ := json.Marshal(request.Limits)
	path := fmt.Sprintf("/v2/sessions/%s/ports/%d/connections/%s", sid, request.Port, request.ID)
	req, err := http.NewRequestWithContext(bounded, "POST", strings.TrimSuffix(origin, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("cannot create port request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", portTunnelUpgrade)
	req.Header.Set("Content-Type", "application/json")
	// An ordinary JSON request timeout must not become the successful stream's
	// lifetime. Upgrade explicitly disables HTTP/2 and ambient redirects.
	copy := *client
	copy.Timeout = 0
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if transport, ok := client.Transport.(*http.Transport); ok {
		clone := transport.Clone()
		clone.ForceAttemptHTTP2 = false
		clone.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		if clone.TLSClientConfig != nil {
			clone.TLSClientConfig = clone.TLSClientConfig.Clone()
			clone.TLSClientConfig.NextProtos = []string{"http/1.1"}
		}
		clone.Proxy = nil
		copy.Transport = clone
		defer clone.CloseIdleConnections()
	}
	response, err := copy.Do(req)
	if err != nil {
		if bounded.Err() != nil {
			return nil, bounded.Err()
		}
		return nil, errors.New("port open transport failed")
	}
	defer func() {
		if !success {
			_ = response.Body.Close()
		}
	}()
	if response.StatusCode != http.StatusSwitchingProtocols {
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 65537))
		if readErr != nil || len(data) > 65536 {
			return nil, errors.New("invalid bounded port open response")
		}
		var value struct {
			Code string `json:"code"`
		}
		code := "api_error"
		if json.Unmarshal(data, &value) == nil && safePortHTTPCode(value.Code) {
			code = value.Code
		}
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			code = "redirect_rejected"
		}
		return nil, &HTTPPortError{response.StatusCode, code}
	}
	valid := response.ProtoMajor == 1 && response.ProtoMinor == 1
	for key, want := range map[string]string{"Upgrade": portTunnelUpgrade, "X-OSV-Session-ID": sid, "X-OSV-Connection-ID": request.ID, "X-OSV-Port": strconv.Itoa(int(request.Port))} {
		values := response.Header.Values(key)
		valid = valid && len(values) == 1 && values[0] == want
	}
	upgrade := false
	for _, line := range response.Header.Values("Connection") {
		for _, part := range strings.Split(line, ",") {
			if strings.EqualFold(strings.TrimSpace(part), "upgrade") {
				upgrade = true
			}
		}
	}
	stream, ok := response.Body.(io.ReadWriteCloser)
	if !valid || !upgrade || !ok {
		return nil, errPortProtocol
	}
	if !stopStart() || startup.Err() != nil || bounded.Err() != nil {
		return nil, context.Canceled
	}
	inner := &linuxPortStream{connection: stream, reader: bufio.NewReaderSize(stream, portDataLimit+5),
		request: linuxPortRequest{SessionID: sid, ID: request.ID, Port: request.Port, Limits: &request.Limits}, cancel: cancel}
	inner.stop = context.AfterFunc(bounded, func() { _ = stream.Close() })
	if bounded.Err() != nil {
		inner.Close()
		return nil, bounded.Err()
	}
	success = true
	return &HTTPPortTunnel{stream: inner}, nil
}

func safePortHTTPCode(code string) bool {
	if len(code) < 1 || len(code) > 64 {
		return false
	}
	for _, c := range code {
		if c != '_' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
