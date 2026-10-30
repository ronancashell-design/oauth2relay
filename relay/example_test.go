// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package relay_test

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"oauth2relay.com/oauth2relay/v2/config"
	"oauth2relay.com/oauth2relay/v2/relay"
)

// A program that embeds the relay: it reads the configuration, adds a
// middleware and an admin route, and runs until SIGINT or SIGTERM.
func Example() {
	raw, err := config.ReadFile("config.json")
	if err != nil {
		log.Fatal(err)
	}
	cfg, err := config.Parse(raw, nil)
	if err != nil {
		log.Fatal(err)
	}

	requireTenant := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Tenant") == "" {
				http.Error(w, "missing X-Tenant", http.StatusBadRequest)
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	srv, err := relay.New(cfg, relay.Options{
		Version:    "custom-build",
		Middleware: []func(http.Handler) http.Handler{requireTenant},
		AdminRoutes: func(mux *http.ServeMux) {
			mux.HandleFunc("/admin/version", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("custom-build\n"))
			})
		},
		// Needed only when secrets_refresh_interval is set.
		Rebuild: relay.Rebuilder(raw, nil),
	})
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
