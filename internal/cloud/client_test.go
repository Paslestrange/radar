package cloud

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestEscalationWarningKeepsFlagGuidanceOffAnsweredHandshakes(t *testing.T) {
	dialErr := errors.New("websocket: bad handshake")

	answered := escalationWarning(5, handshakeRejectionError(http.StatusForbidden, dialErr))
	if strings.Contains(answered, "--cloud-token") {
		t.Fatalf("a 403 escalation still points at the token: %q", answered)
	}
	if !strings.Contains(answered, "was not checked") {
		t.Fatalf("a 403 escalation drops the reason the handshake gave: %q", answered)
	}

	// No answer at all is the case the flag list is for: a wrong Cloud URL and
	// an unreachable one are indistinguishable from the agent's side.
	unanswered := escalationWarning(5, errors.New("ws dial: dial tcp 10.0.0.1:443: connect: connection refused"))
	for _, want := range []string{"--cloud-url", "--cloud-token", "--cluster-name", "connection refused"} {
		if !strings.Contains(unanswered, want) {
			t.Fatalf("an unanswered-dial escalation is missing %q: %q", want, unanswered)
		}
	}
}

func TestEscalationWarningStillBlamesTheTokenOn401(t *testing.T) {
	// 401 is the one status that IS a verdict on the credential, so the
	// escalation must keep pointing there.
	got := escalationWarning(5, handshakeRejectionError(http.StatusUnauthorized, errors.New("websocket: bad handshake")))
	if !strings.Contains(got, "--cloud-token") {
		t.Fatalf("a 401 escalation no longer points at the token: %q", got)
	}
}
