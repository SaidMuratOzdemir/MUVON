package agentctrl

import (
	"bytes"
	"errors"
	"net/http"
	"time"
)

// RevokedMessage is the error central returns for a key whose agent was
// revoked. It differs from the answer to an unknown key so the agent can say
// why it lost central instead of retrying as if the network were down.
const RevokedMessage = "agent revoked"

// ErrRevoked is what agent-side clients return once central has refused
// their key as revoked.
var ErrRevoked = errors.New(RevokedMessage)

// RevokedRetry spaces out attempts after a revocation. A revoked key never
// works again, so the attempts only keep the condition visible in the log;
// coming back takes restarting the agent with a new key.
const RevokedRetry = 10 * time.Minute

// IsRevoked reports whether an agent API response refused the key as revoked.
func IsRevoked(status int, body []byte) bool {
	return status == http.StatusUnauthorized && bytes.Contains(body, []byte(RevokedMessage))
}
