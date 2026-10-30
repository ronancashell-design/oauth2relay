// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package relay

import (
	"encoding/json"
	"math"
	"net/http"
	"time"

	"oauth2relay.com/oauth2relay/v2/config"
)

// Health checks.
//
// Liveness only says the process is serving HTTP. Readiness says the relay
// can take traffic: the first token has been obtained (or a fixed token is
// configured) and the server is not shutting down.
//
// Readiness deliberately does not fail when a later token renewal fails.
// When the identity provider is down every replica fails alike, and taking
// them all out of the load balancer would turn a clear 503 from the relay
// into connection errors. With token.background_refresh off, a replica out
// of rotation would also never renew its token, since only requests renew
// it. The token state is reported in the body for diagnosis, and alerting
// should use the oauth2relay_token_renewals_total and
// oauth2relay_token_expires_in_seconds metrics.

type tokenStatus struct {
	State            string `json:"state"` // fixed, none, valid, expired or renewal_failed
	ExpiresInSeconds *int64 `json:"expires_in_seconds,omitempty"`
}

type readinessBody struct {
	Status string       `json:"status"` // ready, starting or draining
	Token  *tokenStatus `json:"token,omitempty"`
}

func livenessHandler(w http.ResponseWriter, _ *http.Request) {
	writeHealth(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) readinessHandler(w http.ResponseWriter, _ *http.Request) {
	body := readinessBody{Status: "ready", Token: s.tokenStatus()}
	status := http.StatusOK
	switch {
	case s.draining.Load():
		body.Status, status = "draining", http.StatusServiceUnavailable
	case !s.started.Load():
		body.Status, status = "starting", http.StatusServiceUnavailable
	}
	writeHealth(w, status, body)
}

// tokenStatus describes the access token without revealing it.
func (s *Server) tokenStatus() *tokenStatus {
	if s.tokens == nil {
		return &tokenStatus{State: "fixed"}
	}
	tok, lastErr := s.tokens.Status()
	if tok == nil {
		return &tokenStatus{State: "none"}
	}
	left := int64(math.Floor(time.Until(tok.ExpiresAt).Seconds()))
	ts := &tokenStatus{State: "valid", ExpiresInSeconds: &left}
	switch {
	case lastErr != nil:
		ts.State = "renewal_failed"
	case left < 0:
		ts.State = "expired"
	}
	return ts
}

func writeHealth(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// registerOperationalEndpoints adds the enabled health and metrics endpoints,
// and Options.AdminRoutes, to mux. The endpoints match their exact path and
// need no API key.
func (s *Server) registerOperationalEndpoints(mux *http.ServeMux, cfg *config.Config) {
	if cfg.Health.IsEnabled() {
		mux.HandleFunc(cfg.Health.LivenessPath, livenessHandler)
		mux.HandleFunc(cfg.Health.ReadinessPath, s.readinessHandler)
	}
	if cfg.Metrics.IsEnabled() {
		mux.Handle(cfg.Metrics.Path, s.metrics.handler())
	}
	if s.opts.AdminRoutes != nil {
		s.opts.AdminRoutes(mux)
	}
}
