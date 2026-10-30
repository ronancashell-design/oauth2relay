// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package token

import (
	"context"
	"log/slog"
	"time"
)

// Background token refresh.
//
// With token.background_refresh (the default) the token is renewed once
// token.refresh_at of its lifetime has passed, so requests do not wait for
// a renewal. When a background renewal fails the current token is used
// until it expires and the renewal is retried with backoff. Requests still
// renew the token themselves if it does expire.

// minRefreshInterval stops very short-lived tokens from being renewed in a
// tight loop.
const minRefreshInterval = time.Second

// RunRefresher renews the token in the background until ctx is done.
func (m *Manager) RunRefresher(ctx context.Context) {
	failures := 0
	for {
		s := m.settings.Load()
		var wait time.Duration
		if failures > 0 {
			base, maxWait := loginRetryTiming(s.Login)
			wait = retryDelay(base, maxWait, failures)
		} else {
			wait = refreshDue(m.Current(), s.Token.RefreshFraction()).Sub(m.now())
		}
		if wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if failures == 0 {
				continue // check again: a request may have renewed the token meanwhile
			}
		}
		if ctx.Err() != nil {
			return
		}

		seen := m.Current()
		if err := m.renewUnlessRenewed(ctx, seen); err != nil {
			failures++
			attrs := []any{"error", err, "consecutive_failures", failures}
			if seen != nil {
				attrs = append(attrs, "token_expires_at", seen.ExpiresAt.Format(time.RFC3339))
			}
			slog.Warn("Background token renewal failed; retrying", attrs...)
			continue
		}
		if failures > 0 {
			slog.Info("Background token renewal recovered", "failed_attempts", failures)
		}
		failures = 0
	}
}

// refreshDue returns when tok should be renewed in the background: after
// refreshAt of its lifetime, but not sooner than minRefreshInterval after it
// was issued. A nil token is due now.
func refreshDue(tok *Token, refreshAt float64) time.Time {
	if tok == nil {
		return time.Now()
	}
	lifetime := tok.ExpiresAt.Sub(tok.IssuedAt)
	delay := max(time.Duration(float64(lifetime)*refreshAt), minRefreshInterval)
	return tok.IssuedAt.Add(delay)
}

// renewUnlessRenewed renews the token unless another renewal replaced seen
// while this one waited for renewMu.
func (m *Manager) renewUnlessRenewed(ctx context.Context, seen *Token) error {
	m.renewMu.Lock()
	defer m.renewMu.Unlock()
	if m.Current() != seen {
		return nil
	}
	slog.Debug("Renewing the access token in the background")
	_, err := m.renewLocked(ctx, seen)
	return err
}
