package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/skyhook-io/radar/internal/auth"
	"github.com/skyhook-io/radar/internal/config"
)

// TestListAgents_Eligible pins the eligibility signal that drives the UI's
// "install an agent to enable this" nudge: true only when the deployment mode
// supports local BYO-agent diagnosis (no proxy/OIDC auth AND /mcp mounted) —
// the same gate the boot-time engine init uses.
func TestListAgents_Eligible(t *testing.T) {
	mcp := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	cases := []struct {
		name string
		mode string
		mcp  http.Handler
		want bool
	}{
		{"local mode + mcp mounted", "none", mcp, true},
		{"auth enabled", "proxy", mcp, false},
		{"mcp disabled", "none", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &Server{authConfig: auth.Config{Mode: c.mode}, mcpHandler: c.mcp}
			rec := httptest.NewRecorder()
			s.handleListAgents(rec, httptest.NewRequest(http.MethodGet, "/api/agents", nil))
			var resp struct {
				Eligible bool `json:"eligible"`
			}
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if resp.Eligible != c.want {
				t.Errorf("eligible = %v, want %v", resp.Eligible, c.want)
			}
		})
	}
}

// TestLocalOriginOK pins the cross-origin guard on the process-spawning POST
// endpoints: same-origin and exact loopback pass; look-alike hosts don't.
func TestLocalOriginOK(t *testing.T) {
	cases := []struct {
		origin string
		want   bool
	}{
		{"", true}, // same-origin / non-browser
		{"http://localhost:9301", true},
		{"http://127.0.0.1:3000", true},
		{"https://localhost", true},
		{"http://[::1]:9301", true},
		{"http://localhost.evil.com", false}, // substring trap
		{"http://127.0.0.1.evil.com", false},
		{"https://evil.com", false},
		{"null", false},
	}
	for _, c := range cases {
		r := &http.Request{Header: http.Header{}}
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		if got := localOriginOK(r); got != c.want {
			t.Errorf("localOriginOK(%q) = %v, want %v", c.origin, got, c.want)
		}
	}
}

// TestConsentMachineScoped pins the shared consent store: recording via the
// endpoint's config path must be visible to currentConsents (what /api/agents
// reports to the panel AND what the CLI reads) — one acknowledgment covers
// both surfaces' checks, per disclosure surface.
func TestConsentMachineScoped(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if c := currentConsents(); c["standard"] || c["cursor"] {
		t.Fatalf("fresh HOME must have no consent, got %v", c)
	}
	if err := config.RecordAIConsent("standard"); err != nil {
		t.Fatal(err)
	}
	c := currentConsents()
	if !c["standard"] || c["cursor"] {
		t.Fatalf("standard consent must not cover cursor's surface: %v", c)
	}
	// A stale (older-version) acknowledgment must not count.
	if _, err := config.Update(func(c *config.Config) {
		c.AIConsent["cursor"] = "v1"
	}); err != nil {
		t.Fatal(err)
	}
	if currentConsents()["cursor"] {
		t.Fatal("an older disclosure version must not satisfy consent")
	}
}
