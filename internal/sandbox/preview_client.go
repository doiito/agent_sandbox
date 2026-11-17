package sandbox

import (
	"errors"
	"regexp"
	"time"
)

var previewClientOrigin = regexp.MustCompile(`^https://[0-9a-f]{24}\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?::[1-9][0-9]{0,4})?$`)
var previewClientSecret = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidateFor verifies a control response, including the create-only bootstrap.
// Revocation is authorization proof, not a guest TCP cleanup receipt.
func (i PreviewGrantInfo) ValidateFor(session, id string, port uint16, creating bool) error {
	invalid := errors.New("invalid preview control proof")
	if i.Protocol != previewProtocol || i.SessionID != session || i.ID != id || i.Port != port || port == 0 || !validSessionID(session) || !validSessionID(id) {
		return invalid
	}
	if _, err := previewHTTPSOrigin(i.Origin); err != nil || !previewClientOrigin.MatchString(i.Origin) {
		return invalid
	}
	if i.CreatedAt.IsZero() || !i.ExpiresAt.After(i.CreatedAt) || i.ExpiresAt.Sub(i.CreatedAt) > 300*time.Second {
		return invalid
	}
	switch i.Status {
	case "active", "revoked", "expired", "session_closed", "server_closed":
	default:
		return invalid
	}
	if creating {
		prefix := i.Origin + previewAuthorizePath + "?token="
		if i.Status != "active" || len(i.BootstrapURL) != len(prefix)+64 || i.BootstrapURL[:len(prefix)] != prefix || !previewClientSecret.MatchString(i.BootstrapURL[len(prefix):]) {
			return invalid
		}
	} else if i.BootstrapURL != "" {
		return invalid
	}
	return nil
}
