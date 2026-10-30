// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

// Package relay is the OAUTH2Relay server: it accepts requests, adds the
// access token and relays them to the configured upstream.
//
// A Server is built from a parsed configuration with New and started with
// Run. Options adds behaviour without changing the core: middleware around
// the relay handler, routes on the admin port, an audit sink, a shared token
// store and a router that chooses among several routes.
package relay

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"oauth2relay.com/oauth2relay/v2/config"
	"oauth2relay.com/oauth2relay/v2/token"
)

// TokenSource returns the access token for a route. *token.Manager is one.
// Token must return when ctx is done; see token.Manager.Token.
type TokenSource interface {
	Token(ctx context.Context) (*token.Token, error)
}

// Route is where a request is relayed and how its access token is
// obtained.
type Route struct {
	// Config holds the relay, inbound authentication and request limit
	// settings for the route.
	Config *config.Config
	// Tokens supplies the access token. It is not used when
	// Config.Relay.FixedToken is set.
	Tokens TokenSource
}

// Router chooses the route for an incoming request. The default router
// sends every request to the single route of the configuration. A router
// that finds no route returns ErrNoRoute.
type Router interface {
	Route(r *http.Request) (*Route, error)
}

// ErrNoRoute is returned by a Router that has no route for a request. The
// caller receives 404 Not Found.
var ErrNoRoute = errors.New("no route for the request")

// AuditRecord describes one finished relayed request.
type AuditRecord struct {
	Time         time.Time // when the request arrived
	RequestID    string
	Method       string
	Path         string
	ClientIP     string
	Status       int
	Duration     time.Duration
	Bytes        int64  // response body size
	UpstreamHost string // empty when no upstream was chosen
	Error        string // the relay's error code, empty on success
}

// AuditSink receives a record of every relayed request, after the response
// has been sent. Audit must not block for long; it runs on the request's
// goroutine.
type AuditSink interface {
	Audit(ctx context.Context, rec AuditRecord)
}

// Options are the optional parts of a Server.
type Options struct {
	// Version is reported in the oauth2relay_build_info metric.
	Version string
	// Router chooses the route for each request (default: the single route
	// of the configuration).
	Router Router
	// Middleware wraps the relay handler, outermost first. It does not wrap
	// the health and metrics endpoints.
	Middleware []func(http.Handler) http.Handler
	// AdminRoutes adds handlers next to the health and metrics endpoints:
	// on admin_port when it is set, otherwise on the relay port.
	AdminRoutes func(mux *http.ServeMux)
	// Audit receives a record of every relayed request (default none).
	Audit AuditSink
	// TokenStore shares the access token between replicas (default none).
	TokenStore token.Store
	// Rebuild returns a fresh, prepared configuration. It is required when
	// secrets_refresh_interval is set; see Rebuilder.
	Rebuild func(ctx context.Context) (*config.Config, error)
}

// Server is one relay: its configuration, token manager, outbound
// transport, metrics and health state. Nothing is shared between Servers
// except the process-wide log redaction.
type Server struct {
	opts Options

	// live holds the configuration in use. Re-fetching secrets replaces it.
	live      atomic.Pointer[config.Config]
	tokens    *token.Manager // nil when relay.fixedtoken is set
	router    Router
	metrics   *metrics
	transport *http.Transport
	guarded   sync.Map // allowed_networks key -> *http.Transport

	// started is set once the first token has been obtained.
	started atomic.Bool
	// draining is set when shutdown begins.
	draining atomic.Bool
}

// New returns a Server for cfg, which must come from config.Parse. Its
// secret placeholders are resolved by Run; call Prepare first to resolve
// them sooner.
func New(cfg *config.Config, opts Options) (*Server, error) {
	if cfg.SecretsRefreshInterval > 0 && opts.Rebuild == nil {
		return nil, fmt.Errorf("secrets_refresh_interval is set but Options.Rebuild is nil")
	}
	s := &Server{
		opts:      opts,
		metrics:   newMetrics(opts.Version),
		transport: newTransport(),
	}
	s.live.Store(cfg)
	if cfg.Relay.FixedToken == "" {
		s.tokens = token.NewManager(token.SettingsFrom(cfg), token.Options{
			Transport: s.transport,
			Store:     opts.TokenStore,
			Observer:  s.metrics,
		})
		s.metrics.registerTokenExpiry(s.tokens)
	}
	s.router = opts.Router
	if s.router == nil {
		s.router = singleRoute{s}
	}
	return s, nil
}

// Tokens returns the server's token manager, or nil when relay.fixedtoken
// is set.
func (s *Server) Tokens() *token.Manager { return s.tokens }

// MetricsRegistry returns the server's Prometheus registry, so that
// extensions can add their own metrics.
func (s *Server) MetricsRegistry() *prometheus.Registry { return s.metrics.registry }

// Config returns the configuration in use.
func (s *Server) Config() *config.Config { return s.live.Load() }

// setConfig puts a re-fetched configuration in use.
func (s *Server) setConfig(cfg *config.Config) {
	s.live.Store(cfg)
	if s.tokens != nil {
		s.tokens.Update(token.SettingsFrom(cfg))
	}
}

// singleRoute is the default Router: every request goes to the one route
// of the configuration in use.
type singleRoute struct{ s *Server }

func (r singleRoute) Route(*http.Request) (*Route, error) {
	return &Route{Config: r.s.live.Load(), Tokens: r.s.tokens}, nil
}

// Handler returns the relay handler wrapped in Options.Middleware. Run
// serves it on the relay port; it is exported for embedding and tests.
func (s *Server) Handler() http.Handler {
	var h http.Handler = http.HandlerFunc(s.relayHandler)
	for i := len(s.opts.Middleware) - 1; i >= 0; i-- {
		h = s.opts.Middleware[i](h)
	}
	return h
}

// Run prepares the configuration, obtains the first access token and
// serves until ctx is done, then shuts down gracefully. It returns nil
// after a shutdown requested through ctx, and an error if startup fails
// or a server stops unexpectedly.
//
// The admin server, if configured, starts first so that liveness passes
// (and readiness reports "starting") while the first token is obtained.
func (s *Server) Run(ctx context.Context) error {
	cfg := s.live.Load()
	serveErr := make(chan error, 2)

	var adminSrv *http.Server
	if cfg.AdminPort != 0 {
		adminMux := http.NewServeMux()
		s.registerOperationalEndpoints(adminMux, cfg)
		adminSrv = newHTTPServer(cfg, cfg.AdminPort, adminMux)
		go func() {
			slog.Info("Admin server listening", "addr", adminSrv.Addr)
			if err := adminSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				serveErr <- fmt.Errorf("admin server: %w", err)
			}
		}()
	}
	// startupFailed stops the admin server and returns err, or nil if ctx
	// was cancelled: a shutdown requested during startup is not an error.
	startupFailed := func(err error) error {
		if adminSrv != nil {
			_ = adminSrv.Close()
		}
		if ctx.Err() != nil {
			slog.Info("Stopped before startup completed")
			return nil
		}
		return err
	}

	if err := Prepare(ctx, cfg); err != nil {
		return startupFailed(fmt.Errorf("failed to prepare the configuration: %w", err))
	}
	if err := s.configureOutboundTLS(cfg); err != nil {
		return startupFailed(fmt.Errorf("failed to load ca_file: %w", err))
	}
	if len(cfg.SecretsManagers) > 0 {
		s.metrics.registerSecrets()
	}

	if s.tokens != nil {
		s.tokens.Update(token.SettingsFrom(cfg))
		slog.Info("Obtaining the initial access token")
		if _, err := s.tokens.Token(ctx); err != nil {
			return startupFailed(fmt.Errorf("failed to get initial valid token: %w", err))
		}
		slog.Info("Initial access token obtained")
	}

	mux := http.NewServeMux()
	if cfg.AdminPort == 0 {
		s.registerOperationalEndpoints(mux, cfg)
	}
	mux.Handle("/", s.Handler())
	srv := newHTTPServer(cfg, cfg.Port, mux)
	if cfg.TLS.Enabled() {
		tlsCfg, reloader, err := serverTLSConfig(&cfg.TLS)
		if err != nil {
			return startupFailed(fmt.Errorf("failed to set up TLS: %w", err))
		}
		srv.TLSConfig = tlsCfg
		s.metrics.registerCertificate(reloader)
	}

	go func() {
		slog.Info("Relay server listening", "addr", srv.Addr, "relay_mode", cfg.Relay.Mode, "tls", cfg.TLS.Enabled())
		var err error
		if cfg.TLS.Enabled() {
			err = srv.ListenAndServeTLS("", "") // the certificate comes from TLSConfig.GetCertificate
		} else {
			err = srv.ListenAndServe()
		}
		if !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()
	// Background work stops when Run returns.
	bgCtx, stopBackground := context.WithCancel(ctx)
	defer stopBackground()
	if s.tokens != nil && cfg.Token.BackgroundRefreshEnabled() {
		go s.tokens.RunRefresher(bgCtx)
	}
	if n := cfg.SecretsRefreshInterval; n > 0 {
		slog.Info("Secrets will be re-fetched periodically", "interval_seconds", n)
		go s.runSecretRefresher(bgCtx, time.Duration(n)*time.Second)
	}
	s.started.Store(true)

	select {
	case err := <-serveErr:
		_ = srv.Close()
		if adminSrv != nil {
			_ = adminSrv.Close()
		}
		return fmt.Errorf("server failed: %w", err)
	case <-ctx.Done():
		s.shutdown(cfg, srv, adminSrv)
		return nil
	}
}

// shutdown marks the relay as draining, waits server.shutdown_delay seconds
// so load balancers see readiness fail, then stops accepting connections and
// gives in-flight requests up to server.shutdown_timeout seconds to finish.
func (s *Server) shutdown(cfg *config.Config, srv, adminSrv *http.Server) {
	s.draining.Store(true)
	if d := cfg.Server.ShutdownDelay; d > 0 {
		slog.Info("Shutdown signal received, waiting before draining", "shutdown_delay_seconds", d)
		time.Sleep(time.Duration(d) * time.Second)
	}
	slog.Info("Draining in-flight requests", "shutdown_timeout_seconds", cfg.Server.ShutdownTimeout)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Server.ShutdownTimeout)*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("Graceful shutdown incomplete", "error", err)
	}
	// The admin server stays up while the relay drains, then stops.
	if adminSrv != nil {
		_ = adminSrv.Shutdown(shutdownCtx)
	}
	slog.Info("Server stopped")
}

// newHTTPServer builds an inbound HTTP server on port with the configured
// limits.
func newHTTPServer(cfg *config.Config, port int, handler http.Handler) *http.Server {
	sec := func(n int) time.Duration { return time.Duration(n) * time.Second }
	return &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.Host, port),
		Handler:           handler,
		ReadHeaderTimeout: sec(cfg.Server.ReadHeaderTimeout),
		ReadTimeout:       sec(cfg.Server.ReadTimeout),
		WriteTimeout:      sec(cfg.Server.WriteTimeout),
		IdleTimeout:       sec(cfg.Server.IdleTimeout),
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
	}
}
