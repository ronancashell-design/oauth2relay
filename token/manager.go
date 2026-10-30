// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package token

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"oauth2relay.com/oauth2relay/v2/config"
	"oauth2relay.com/oauth2relay/v2/internal/util"
)

// Defaults for retrying a failed login.
const (
	defaultLoginRetryAttempts    = 5
	defaultLoginRetryInterval    = 5  // seconds before the first retry
	defaultLoginRetryMaxInterval = 60 // seconds
)

// ErrWaitTimeout is returned by Manager.Token when the context's deadline
// passed before a token became available. The renewal carries on, so a
// later call can use its result.
var ErrWaitTimeout = errors.New("timed out waiting for a valid token")

// Settings are the parts of the configuration that say how one connection
// obtains its token.
type Settings struct {
	Login   *config.LoginConfig
	Refresh *config.RefreshConfig
	Token   config.TokenConfig
}

// SettingsFrom returns the token settings of cfg.
func SettingsFrom(cfg *config.Config) *Settings {
	return &Settings{Login: cfg.Login, Refresh: cfg.Refresh, Token: cfg.Token}
}

// Store keeps a connection's token outside the process, so that several
// relay replicas can share one token instead of each obtaining its own.
// The Manager always keeps its own copy as well: it loads from the Store
// before renewing, in case another replica has already done so, and saves
// every token it obtains.
//
// A Store that also implements Locker is locked while a token is renewed,
// so replicas do not renew at the same time.
type Store interface {
	Load(ctx context.Context) (*Token, error)
	Save(ctx context.Context, tok *Token) error
}

// Locker serialises renewal across processes. Lock returns a function that
// releases the lock.
type Locker interface {
	Lock(ctx context.Context) (unlock func(), err error)
}

// Observer is told about requests to the token endpoint, for metrics.
type Observer interface {
	// ObserveRenewal is called after each login or refresh request. kind is
	// "login" or "refresh". Refreshes that were not attempted (no refresh
	// token or no refresh configuration) are not reported.
	ObserveRenewal(kind string, err error)
	// ObserveIdPRequest is called with the duration of each request. kind
	// is "login" or "refresh", or "exchange" for an Exchanger.
	ObserveIdPRequest(kind string, elapsed time.Duration)
}

// Options are the optional dependencies of a Manager.
type Options struct {
	// Transport sends the token requests (default http.DefaultTransport).
	Transport http.RoundTripper
	// Store shares the token with other processes (default none).
	Store Store
	// Observer receives token endpoint metrics (default none).
	Observer Observer
	// Now returns the current time (default time.Now).
	Now func() time.Time
}

// Manager obtains and renews the access token of one connection. Only one
// renewal runs at a time; callers that arrive during a renewal wait for it
// and share its result.
type Manager struct {
	settings  atomic.Pointer[Settings]
	transport http.RoundTripper
	store     Store
	observer  Observer
	now       func() time.Time

	// renewMu serialises renewal so that concurrent callers do not each
	// run their own refresh/login (and retry) cycle.
	renewMu sync.Mutex

	// mu guards the fields below.
	mu  sync.Mutex
	tok *Token
	// gen counts completed renewal cycles and lastErr holds the outcome of
	// the most recent one.
	gen     uint64
	lastErr error
}

// NewManager returns a Manager for s.
func NewManager(s *Settings, opts Options) *Manager {
	m := &Manager{
		transport: opts.Transport,
		store:     opts.Store,
		observer:  opts.Observer,
		now:       opts.Now,
	}
	if m.transport == nil {
		m.transport = http.DefaultTransport
	}
	if m.observer == nil {
		m.observer = nopObserver{}
	}
	if m.now == nil {
		m.now = time.Now
	}
	m.settings.Store(s)
	return m
}

// Update replaces the settings, for example after secrets were re-fetched.
// The current token is kept.
func (m *Manager) Update(s *Settings) {
	m.settings.Store(s)
}

// Current returns the token held, which may be nil or expired.
func (m *Manager) Current() *Token {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tok
}

// Set replaces the token held, without contacting the identity provider,
// and clears the error of the latest renewal. Extensions use it to install
// a token obtained elsewhere.
func (m *Manager) Set(tok *Token) {
	m.record(tok, nil)
}

// Status returns the token held and the error of the latest renewal, nil if
// it succeeded.
func (m *Manager) Status() (*Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tok, m.lastErr
}

func (m *Manager) expired(tok *Token) bool {
	return m.now().After(tok.ExpiresAt)
}

// Token returns a valid token, renewing it first if it is missing or
// expired. It returns when ctx is done even if the renewal has not
// finished: with ErrWaitTimeout if ctx's deadline passed, otherwise with
// ctx's error. The renewal carries on in the background.
func (m *Manager) Token(ctx context.Context) (*Token, error) {
	if tok := m.Current(); tok != nil && !m.expired(tok) {
		return tok, nil
	}
	type result struct {
		token *Token
		err   error
	}
	ch := make(chan result, 1) // buffered so the goroutine never blocks
	go func() {
		tok, err := m.renewIfExpired(context.WithoutCancel(ctx))
		ch <- result{tok, err}
	}()
	select {
	case res := <-ch:
		return res.token, res.err
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, ErrWaitTimeout
		}
		return nil, ctx.Err()
	}
}

// renewIfExpired renews the token unless it is valid, or another caller
// renewed it while this one waited.
func (m *Manager) renewIfExpired(ctx context.Context) (*Token, error) {
	m.mu.Lock()
	token, gen := m.tok, m.gen
	m.mu.Unlock()
	if token == nil {
		slog.Debug("No access token held; obtaining one")
	} else if m.expired(token) {
		slog.Debug("Access token expired; renewing", "expired_at", token.ExpiresAt)
	}

	// Only one goroutine renews at a time; others wait and then reuse the
	// outcome of the renewal that finished while they were waiting.
	m.renewMu.Lock()
	defer m.renewMu.Unlock()

	m.mu.Lock()
	token = m.tok
	finished, lastErr := m.gen != gen, m.lastErr
	m.mu.Unlock()
	if token != nil && !m.expired(token) {
		slog.Debug("Access token renewed by another request; reusing it")
		return token, nil
	}
	if finished && lastErr != nil {
		// A full refresh/login cycle failed while we were waiting; don't
		// immediately start another one.
		return nil, lastErr
	}
	return m.renewLocked(ctx, nil)
}

// renewLocked runs one renewal cycle and records its outcome. With a Store
// it first adopts a stored token that is newer than seen and still valid.
// Callers hold renewMu.
func (m *Manager) renewLocked(ctx context.Context, seen *Token) (*Token, error) {
	if m.store != nil {
		if locker, ok := m.store.(Locker); ok {
			unlock, err := locker.Lock(ctx)
			if err != nil {
				slog.Warn("Could not lock the token store; renewing without the lock", "error", err)
			} else {
				defer unlock()
			}
		}
		stored, err := m.store.Load(ctx)
		if err != nil {
			slog.Warn("Could not load the token from the token store", "error", err)
		} else if stored != nil && stored != seen && !m.expired(stored) &&
			(seen == nil || stored.IssuedAt.After(seen.IssuedAt)) {
			slog.Debug("Using the access token from the token store")
			m.record(stored, nil)
			return stored, nil
		}
	}

	newToken, err := m.renew(ctx, m.settings.Load())
	m.record(newToken, err)
	if err == nil && m.store != nil {
		if err := m.store.Save(ctx, newToken); err != nil {
			slog.Warn("Could not save the token to the token store", "error", err)
		}
	}
	return newToken, err
}

// record stores the outcome of a renewal cycle.
func (m *Manager) record(newToken *Token, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gen++
	m.lastErr = err
	if err == nil {
		m.tok = newToken
	}
}

// renew attempts a token refresh. If that fails and login configuration
// exists, it falls back to a login (with retries).
func (m *Manager) renew(ctx context.Context, s *Settings) (*Token, error) {
	newToken, err := m.refresh(ctx, s)
	m.observeRenewal("refresh", err)
	if err == nil {
		return newToken, nil
	}
	if s.Login == nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}
	if errors.Is(err, errRefreshUnavailable) {
		slog.Debug("No refresh token; logging in", "reason", err)
	} else {
		slog.Warn("Token refresh failed; logging in instead", "error", err)
	}
	newToken, err = m.loginWithRetry(ctx, s)
	if err != nil {
		return nil, fmt.Errorf("both refresh and login failed: %w", err)
	}
	return newToken, nil
}

// observeRenewal reports a login or refresh request to the Observer.
// Refreshes that were never sent are not reported.
func (m *Manager) observeRenewal(kind string, err error) {
	if errors.Is(err, errRefreshUnavailable) {
		return
	}
	m.observer.ObserveRenewal(kind, err)
}

// loginWithRetry calls login up to login.retry_attempts times. The wait
// before each retry starts at login.retry_interval and doubles up to
// login.retry_max_interval, with jitter so that replicas do not retry in
// step. Each failure is logged together with the time of the next attempt.
func (m *Manager) loginWithRetry(ctx context.Context, s *Settings) (*Token, error) {
	attempts := s.Login.RetryAttempts
	if attempts <= 0 {
		attempts = defaultLoginRetryAttempts
	}
	base, maxWait := loginRetryTiming(s.Login)

	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		var newToken *Token
		newToken, err = m.login(ctx, s)
		m.observeRenewal("login", err)
		if err == nil {
			if attempt > 1 {
				slog.Info("Login succeeded after retrying", "attempt", attempt, "attempts", attempts)
			}
			return newToken, nil
		}
		if IsPermanent(err) {
			slog.Error("Login failed; not retrying because the error is permanent",
				"attempt", attempt, "attempts", attempts, "error", err)
			return nil, fmt.Errorf("login failed: %w", err)
		}
		if attempt == attempts {
			slog.Error("Login failed; no retries remaining", "attempt", attempt, "attempts", attempts, "error", err)
			break
		}
		wait := retryDelay(base, maxWait, attempt)
		slog.Warn("Login failed; retrying", "attempt", attempt, "attempts", attempts, "error", err,
			"next_attempt", time.Now().Add(wait).Format(time.RFC3339))
		if !sleep(ctx, wait) {
			return nil, fmt.Errorf("login abandoned: %w", ctx.Err())
		}
	}
	return nil, fmt.Errorf("login failed after %d attempts: %w", attempts, err)
}

// sleep waits for d, or until ctx is done. It reports whether d passed.
func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// loginRetryTiming returns the first and the longest wait between login
// attempts. lc may be nil.
func loginRetryTiming(lc *config.LoginConfig) (base, maxWait time.Duration) {
	baseSecs, maxSecs := defaultLoginRetryInterval, defaultLoginRetryMaxInterval
	if lc != nil {
		if lc.RetryInterval > 0 {
			baseSecs = lc.RetryInterval
		}
		if lc.RetryMaxInterval > 0 {
			maxSecs = lc.RetryMaxInterval
		}
	}
	// An interval configured above the cap keeps the wait constant, as
	// retry_interval did before backoff existed.
	maxSecs = max(maxSecs, baseSecs)
	return time.Duration(baseSecs) * time.Second, time.Duration(maxSecs) * time.Second
}

// retryDelay returns the wait before retry n (1 for the first): base doubled
// for each earlier retry and capped at maxWait, then shortened at random by
// up to half.
func retryDelay(base, maxWait time.Duration, n int) time.Duration {
	d := base
	for i := 1; i < n && d < maxWait; i++ {
		d *= 2
	}
	d = min(d, maxWait)
	return d/2 + rand.N(d/2+1) //nolint:gosec // G404: jitter, not a secret
}

// login sends the configured login request and returns the new token.
func (m *Manager) login(ctx context.Context, s *Settings) (*Token, error) {
	lc := s.Login
	if lc == nil {
		return nil, fmt.Errorf("login configuration is not provided")
	}
	slog.Debug("Sending login request", "grant_type", lc.GrantType)

	// Build the request body and headers based on grant type.
	data, headers, err := buildGrantRequest(lc)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errLoginConfig, err)
	}

	method := lc.Method
	if lc.GrantType != "" {
		// OAuth2 token requests should always be POST
		method = "POST"
	}

	var body io.Reader = nil
	if method == "POST" && data != "" {
		body = bytes.NewBuffer([]byte(data))
	}

	slog.Debug("Login request", "url", lc.URL, "method", method, "headers", headers, "data", data)

	req, err := http.NewRequestWithContext(ctx, method, lc.URL, body)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	respMap, err := m.doTokenRequest(req, lc.Timeout, "Login")
	if err != nil {
		return nil, err
	}
	newToken, err := extractToken(respMap, lc.Parameters, &s.Token, m.now())
	if err != nil {
		return nil, err
	}
	slog.Info("Login successful", "token", newToken)
	return newToken, nil
}

// refresh sends the configured refresh request with the held refresh token
// (or refresh.token if none is held) and returns the new token.
func (m *Manager) refresh(ctx context.Context, s *Settings) (*Token, error) {
	rc := s.Refresh
	if rc == nil {
		return nil, fmt.Errorf("%w: refresh configuration is not provided", errRefreshUnavailable)
	}
	vars := map[string]string{
		"DATA": rc.Data,
	}
	if current := m.Current(); current != nil && current.RefreshToken != "" {
		vars["REFRESHTOKEN"] = current.RefreshToken
	} else if rc.Token != "" {
		vars["REFRESHTOKEN"] = rc.Token
	} else {
		return nil, fmt.Errorf("%w: no refresh token available", errRefreshUnavailable)
	}

	urlStr := util.Substitute(rc.URL, vars)
	dataStr := util.Substitute(rc.Data, vars)
	method := rc.Method

	headers := make(map[string]string)
	for k, v := range rc.Headers {
		headers[k] = util.Substitute(v, vars)
	}

	slog.Debug("Refresh request", "url", urlStr, "method", method, "headers", headers, "data", dataStr)

	var body io.Reader = nil
	if method == "POST" && dataStr != "" {
		body = bytes.NewBuffer([]byte(dataStr))
	}

	req, err := http.NewRequestWithContext(ctx, method, urlStr, body)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	respMap, err := m.doTokenRequest(req, rc.Timeout, "Refresh")
	if err != nil {
		return nil, err
	}
	newToken, err := extractToken(respMap, rc.Parameters, &s.Token, m.now())
	if err != nil {
		return nil, err
	}
	slog.Info("Token refresh successful", "token", newToken)
	return newToken, nil
}

type nopObserver struct{}

func (nopObserver) ObserveRenewal(string, error)            {}
func (nopObserver) ObserveIdPRequest(string, time.Duration) {}
