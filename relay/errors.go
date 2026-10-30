// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package relay

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"oauth2relay.com/oauth2relay/v2/config"
	"oauth2relay.com/oauth2relay/v2/internal/util"
)

// Request IDs, request logging and error responses.

const requestIDHeader = "X-Request-ID"

// validRequestID limits caller-supplied request IDs to a safe length and
// character set, so they cannot inject text into logs.
var validRequestID = regexp.MustCompile(`^[A-Za-z0-9._:\-]{1,128}$`)

// requestInfo identifies one incoming request in logs and error responses,
// and collects what is logged and measured when it finishes.
type requestInfo struct {
	srv *Server
	ID  string
	r   *http.Request
	log *slog.Logger // carries request_id

	start        time.Time
	upstreamHost string // metrics label; empty until an upstream is chosen
	errCode      string // set when the relay itself rejected or failed the request
	errDetail    error
}

// newRequestInfo uses the caller's X-Request-ID if it is well formed, or
// generates one, and echoes it in the response.
func (s *Server) newRequestInfo(w http.ResponseWriter, r *http.Request) *requestInfo {
	id := r.Header.Get(requestIDHeader)
	if !validRequestID.MatchString(id) {
		if gen, err := util.RandomID(); err == nil {
			id = gen
		} else {
			id = "unknown"
		}
	}
	w.Header().Set(requestIDHeader, id)
	return &requestInfo{
		srv:   s,
		ID:    id,
		r:     r,
		log:   slog.With("request_id", id),
		start: time.Now(),
	}
}

// statusClientClosed is recorded when the caller went away before a
// response was written (the nginx convention).
const statusClientClosed = 499

// finish records metrics for the request, sends it to the audit sink and
// writes its log line: always when access_log is on, otherwise only if the
// relay rejected or failed it. Server errors are logged at warn level,
// everything else at info.
func (ri *requestInfo) finish(sw *statusWriter, cfg *config.Config) {
	elapsed := time.Since(ri.start)
	status := sw.status
	if status == 0 {
		if ri.r.Context().Err() != nil {
			status = statusClientClosed
		} else {
			status = http.StatusOK
		}
	}
	ri.srv.metrics.observeRequest(status, ri.upstreamHost, elapsed)
	ip := clientIP(ri.r, cfg.TrustedNetworks())
	if audit := ri.srv.opts.Audit; audit != nil {
		audit.Audit(ri.r.Context(), AuditRecord{
			Time:         ri.start,
			RequestID:    ri.ID,
			Method:       ri.r.Method,
			Path:         ri.r.URL.Path,
			ClientIP:     ip,
			Status:       status,
			Duration:     elapsed,
			Bytes:        sw.bytes,
			UpstreamHost: ri.upstreamHost,
			Error:        ri.errCode,
		})
	}

	if !cfg.AccessLogEnabled() && ri.errCode == "" {
		return
	}
	level := slog.LevelInfo
	if status >= 500 {
		level = slog.LevelWarn
	}
	attrs := []slog.Attr{
		slog.String("method", ri.r.Method),
		slog.String("path", ri.r.URL.Path),
		slog.String("client_ip", ip),
		slog.Int("status", status),
		slog.Float64("duration_ms", float64(elapsed.Microseconds())/1000),
		slog.Int64("bytes", sw.bytes),
	}
	if ri.upstreamHost != "" {
		attrs = append(attrs, slog.String("upstream_host", ri.upstreamHost))
	}
	if ri.errCode != "" {
		attrs = append(attrs, slog.String("error", ri.errCode))
	}
	if ri.errDetail != nil {
		attrs = append(attrs, slog.Any("detail", ri.errDetail))
	}
	ri.log.LogAttrs(ri.r.Context(), level, "request", attrs...)
}

// errorBody is the JSON body of every error the relay itself returns.
type errorBody struct {
	Error     string `json:"error"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

// fail sends the caller only status, a short error code and a safe
// message. detail (which may hold internal information) is only logged,
// on the request's log line.
func (ri *requestInfo) fail(w http.ResponseWriter, status int, code, message string, detail error) {
	ri.errCode, ri.errDetail = code, detail
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Error: code, Message: message, RequestID: ri.ID})
}

// statusWriter records the status code and body size of a response.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (sw *statusWriter) WriteHeader(code int) {
	if sw.status == 0 {
		sw.status = code
	}
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	if sw.status == 0 {
		sw.status = http.StatusOK
	}
	n, err := sw.ResponseWriter.Write(b)
	sw.bytes += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (sw *statusWriter) Unwrap() http.ResponseWriter {
	return sw.ResponseWriter
}
