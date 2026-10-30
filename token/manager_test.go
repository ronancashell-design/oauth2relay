// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package token

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// memStore is a Store shared by Managers in the same test, standing in for
// a shared cache such as Redis.
type memStore struct {
	mu     sync.Mutex
	tok    *Token
	saves  atomic.Int32
	failAt string // "load" or "save" to fail that call
}

func (s *memStore) Load(context.Context) (*Token, error) {
	if s.failAt == "load" {
		return nil, errors.New("store down")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tok == nil {
		return nil, nil
	}
	copied := *s.tok
	return &copied, nil
}

func (s *memStore) Save(_ context.Context, tok *Token) error {
	if s.failAt == "save" {
		return errors.New("store down")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saves.Add(1)
	s.tok = tok
	return nil
}

// lockingStore is a memStore that also implements Locker.
type lockingStore struct {
	memStore
	lock  sync.Mutex
	locks atomic.Int32
}

func (s *lockingStore) Lock(context.Context) (func(), error) {
	s.locks.Add(1)
	s.lock.Lock()
	return s.lock.Unlock, nil
}

func TestManagerSharesTokenThroughStore(t *testing.T) {
	idp, calls := newTokenEndpoint(t, [3]string{"200", "application/json", okTokenJSON})
	cfg := loginConfig(idp.URL, 1)
	store := &lockingStore{}

	first := NewManager(SettingsFrom(cfg), Options{Store: store})
	tok, err := first.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if store.saves.Load() != 1 || store.locks.Load() != 1 {
		t.Errorf("saves = %d, locks = %d; want 1 and 1", store.saves.Load(), store.locks.Load())
	}

	// A second replica adopts the stored token instead of logging in.
	second := NewManager(SettingsFrom(cfg), Options{Store: store})
	got, err := second.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != tok.AccessToken || calls.Load() != 1 {
		t.Errorf("second replica got %q after %d IdP calls; want the stored token and 1 call", got.AccessToken, calls.Load())
	}
}

func TestManagerIgnoresExpiredStoredToken(t *testing.T) {
	idp, calls := newTokenEndpoint(t, [3]string{"200", "application/json", okTokenJSON})
	store := &memStore{tok: &Token{AccessToken: "old", IssuedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(-time.Minute)}}
	m := NewManager(SettingsFrom(loginConfig(idp.URL, 1)), Options{Store: store})
	tok, err := m.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "tok-1" || calls.Load() != 1 {
		t.Errorf("got %q after %d IdP calls; want a fresh login", tok.AccessToken, calls.Load())
	}
}

func TestManagerStoreFailuresDoNotStopRenewal(t *testing.T) {
	for _, failAt := range []string{"load", "save"} {
		t.Run(failAt, func(t *testing.T) {
			idp, _ := newTokenEndpoint(t, [3]string{"200", "application/json", okTokenJSON})
			m := NewManager(SettingsFrom(loginConfig(idp.URL, 1)), Options{Store: &memStore{failAt: failAt}})
			if _, err := m.Token(context.Background()); err != nil {
				t.Errorf("Token with a failing store: %v", err)
			}
		})
	}
}

// blockingTransport holds every request until release is closed.
type blockingTransport struct{ release chan struct{} }

func (b blockingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	<-b.release
	return http.DefaultTransport.RoundTrip(r)
}

func TestManagerTokenWaitTimeout(t *testing.T) {
	release := make(chan struct{})
	idp, _ := newTokenEndpoint(t, [3]string{"200", "application/json", okTokenJSON})
	m := NewManager(SettingsFrom(loginConfig(idp.URL, 1)), Options{Transport: blockingTransport{release}})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := m.Token(ctx); !errors.Is(err, ErrWaitTimeout) {
		t.Fatalf("err = %v, want ErrWaitTimeout", err)
	}

	// The renewal carries on and its result is used by later callers.
	close(release)
	waitFor(t, "the renewal to finish", 2*time.Second, func() bool { return m.Current() != nil })

	cancelled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	m.Set(&Token{AccessToken: "expired", ExpiresAt: time.Now().Add(-time.Second)})
	if _, err := m.Token(cancelled); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v with a cancelled context, want context.Canceled", err)
	}
}

// recordingObserver records what a Manager reports.
type recordingObserver struct {
	mu       sync.Mutex
	renewals []string
	requests int
}

func (o *recordingObserver) ObserveRenewal(kind string, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	result := "success"
	if err != nil {
		result = "failure"
	}
	o.renewals = append(o.renewals, kind+":"+result)
}

func (o *recordingObserver) ObserveIdPRequest(string, time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.requests++
}

func TestManagerObserver(t *testing.T) {
	idp, _ := newTokenEndpoint(t, [3]string{"200", "application/json", okTokenJSON})
	obs := &recordingObserver{}
	// Without a refresh configuration the refresh is not attempted, so only
	// the login is reported.
	m := NewManager(SettingsFrom(loginConfig(idp.URL, 1)), Options{Observer: obs})
	if _, err := m.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(obs.renewals) != 1 || obs.renewals[0] != "login:success" || obs.requests != 1 {
		t.Errorf("observed renewals %v and %d requests; want [login:success] and 1", obs.renewals, obs.requests)
	}
}

func TestManagerClock(t *testing.T) {
	idp, _ := newTokenEndpoint(t, [3]string{"200", "application/json", okTokenJSON})
	issued := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	var now atomic.Pointer[time.Time]
	now.Store(&issued)
	m := NewManager(SettingsFrom(loginConfig(idp.URL, 1)), Options{Now: func() time.Time { return *now.Load() }})
	tok, err := m.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !tok.IssuedAt.Equal(issued) {
		t.Errorf("IssuedAt = %v, want the injected time %v", tok.IssuedAt, issued)
	}
	// The token expires by the injected clock, not the real one.
	later := issued.Add(2 * time.Hour)
	now.Store(&later)
	if !m.expired(tok) {
		t.Error("token not expired two hours after issue by the injected clock")
	}
}
