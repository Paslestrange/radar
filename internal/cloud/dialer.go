package cloud

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
)

const selfUpgradeAvailableHeader = "X-Radar-Self-Upgrade-Available"

// dial establishes a WebSocket to Radar Cloud, authenticates with the
// cluster bearer token, and returns a yamux session with this side as the
// *server*. Cloud opens streams (one per browser request); we accept them.
func dial(ctx context.Context, cfg Config, selfUpgrade bool) (*yamux.Session, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("parse cloud URL: %w", err)
	}
	q := u.Query()
	q.Set("cluster_id", cfg.ClusterID)
	q.Set("cluster_name", cfg.ClusterName)
	u.RawQuery = q.Encode()

	headers := cloudHandshakeHeaders(cfg, selfUpgrade)

	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = 10 * time.Second
	if cfg.InsecureSkipVerify {
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // user-requested via --cloud-insecure-skip-verify for a self-signed hub
	}
	ws, resp, err := dialer.DialContext(ctx, u.String(), headers)
	if err != nil {
		if resp != nil {
			defer resp.Body.Close()
			return nil, handshakeRejectionError(resp.StatusCode, err)
		}
		return nil, fmt.Errorf("ws dial: %w", err)
	}

	// We are the yamux *server* (accepts streams). Cloud is the client
	// (opens streams when browser requests arrive).
	mux, err := yamux.Server(newWSConn(ws), tunnelYamuxConfig())
	if err != nil {
		ws.Close()
		return nil, fmt.Errorf("yamux server setup: %w", err)
	}
	return mux, nil
}

// cloudHandshakeHeaders builds the metadata Radar advertises when opening a
// Cloud tunnel. The self-upgrade capability is deliberately always present:
// false is meaningful for GitOps and --no-self-upgrade installations and must
// not be confused with an older agent that predates the capability contract.
func cloudHandshakeHeaders(cfg Config, selfUpgrade bool) http.Header {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+cfg.Token)
	headers.Set("X-Radar-Version", Version)
	headers.Set(selfUpgradeAvailableHeader, strconv.FormatBool(selfUpgrade))
	if cfg.Namespace != "" {
		headers.Set("X-Radar-Namespace", cfg.Namespace)
	}
	if cfg.Release != "" {
		headers.Set("X-Radar-Release", cfg.Release)
	}
	// Validate before send — the value comes from a ConfigMap on the
	// cluster, and a corrupted ConfigMap shouldn't be able to inject
	// header smuggling. Reject silently on bad shape; hub falls back
	// to name-based correlation.
	if apiURL, err := validateAPIServerURL(cfg.APIServerURL); err == nil && apiURL != "" {
		headers.Set("X-Radar-API-Server-URL", apiURL)
	}
	return headers
}

// tunnelYamuxConfig is the yamux config for the Cloud tunnel. It differs from
// yamux's defaults only in MaxStreamWindowSize.
//
// Per-stream throughput over yamux is capped at window/RTT, and yamux v0.1.2 has
// no RTT-based window auto-tuning, so the ceiling is committed per-stream and
// must be set statically. yamux's 256KB default throttles a single stream to
// under 2MB/s across an intercontinental hop (100-200ms RTT); 4MB lifts that to
// ~27MB/s at 150ms RTT.
//
// This is our *receive* window — it governs the hub→agent direction (request
// bodies, exec stdin, apply payloads), which is small, so the value is not
// load-bearing here. The bulk path is responses (agent→hub), gated by the hub's
// own window (radar-hub tunnelYamuxConfig). We keep this side aligned at 4MB for
// symmetry; the customer binary is single-tenant, so the per-stream buffer cost
// is negligible.
func tunnelYamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.MaxStreamWindowSize = 4 << 20 // 4MB
	return cfg
}

// handshakeRejectionError explains a non-101 answer to the tunnel handshake.
//
// Radar Cloud's /agent endpoint answers a handshake with 101, 401 or 500 and
// nothing else, so 401 is the only status that is a verdict on the cluster
// token. Every other status was written by something on the path in between,
// which never saw the token. That distinction is what the wording protects:
// while Radar Cloud is unreachable its edge answers for it, and blaming the
// credential there sends an operator to rotate a token that was never in
// question, during an outage that clears on its own.
//
// The 401 and 403 wordings are pinned to that endpoint contract. If Radar
// Cloud ever starts answering 403 on /agent, this has to move with it.
func handshakeRejectionError(statusCode int, dialErr error) error {
	var explained error
	switch {
	case statusCode == http.StatusUnauthorized:
		explained = fmt.Errorf("Radar Cloud rejected the cluster token (401). Check --cloud-token: the token may have been rotated or revoked")
	case statusCode == http.StatusForbidden:
		explained = fmt.Errorf("something on the path to Radar Cloud refused the connection (403). Radar Cloud does not answer 403 on its agent endpoint, so the cluster token was not checked. Look at any proxy, gateway or egress policy in front of the Cloud URL")
	case statusCode == http.StatusNotFound:
		explained = fmt.Errorf("nothing serves the Radar Cloud agent endpoint at this URL (404). Check --cloud-url")
	case statusCode >= 500 && statusCode <= 599:
		explained = fmt.Errorf("Radar Cloud did not complete the handshake (status=%d). The cluster token was not rejected, so this is a service or network failure: %w", statusCode, dialErr)
	default:
		explained = fmt.Errorf("unexpected answer to the Radar Cloud handshake (status=%d): %w", statusCode, dialErr)
	}
	return &handshakeStatusError{err: explained}
}

// handshakeStatusError marks a failure where the handshake was answered with
// an HTTP status, as opposed to never reaching a server at all. Every message
// above already names what to check, so the reconnect loop suppresses its
// generic "verify your flags" hint for these.
type handshakeStatusError struct {
	err error
}

func (e *handshakeStatusError) Error() string { return e.err.Error() }

func (e *handshakeStatusError) Unwrap() error { return e.err }
