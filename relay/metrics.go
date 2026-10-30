// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Fijomi Systems SL

package relay

import (
	"net/http"
	"runtime"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"oauth2relay.com/oauth2relay/v2/token"
)

// Prometheus metrics.
//
// Each Server has its own registry (not the global default) so that only
// the relay's metrics, the Go runtime and the process are exported.

const metricsNamespace = "oauth2relay"

// metrics holds a Server's collectors. It implements token.Observer.
type metrics struct {
	registry *prometheus.Registry

	requestsTotal       *prometheus.CounterVec
	requestDuration     *prometheus.HistogramVec
	inboundAuthFailures prometheus.Counter
	tokenRenewals       *prometheus.CounterVec
	idpRequestDuration  *prometheus.HistogramVec
	secretRefreshes     *prometheus.CounterVec
	secretsLastRefresh  prometheus.Gauge
}

func newMetrics(version string) *metrics {
	m := &metrics{
		registry: prometheus.NewRegistry(),

		requestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "requests_total",
			Help:      "Relayed requests by response status code and upstream host. upstream_host is empty when the request was rejected before an upstream was chosen.",
		}, []string{"code", "upstream_host"}),

		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "request_duration_seconds",
			Help:      "Time to handle a relayed request, including waiting for a token and the upstream call.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"upstream_host"}),

		inboundAuthFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "inbound_auth_failures_total",
			Help:      "Requests rejected because the API key was missing or wrong.",
		}),

		tokenRenewals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "token_renewals_total",
			Help:      "Requests to the token endpoint by type (login or refresh) and result (success or failure).",
		}, []string{"type", "result"}),

		idpRequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "idp_request_duration_seconds",
			Help:      "Time taken by token endpoint requests, by type (login or refresh).",
			Buckets:   prometheus.DefBuckets,
		}, []string{"type"}),

		secretRefreshes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "secret_refreshes_total",
			Help:      "Periodic re-fetches of the secret placeholders (secrets_refresh_interval) by result (success or failure).",
		}, []string{"result"}),

		secretsLastRefresh: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "secrets_last_refresh_timestamp_seconds",
			Help:      "Unix time when the secret placeholders were last resolved successfully, at startup or by a re-fetch.",
		}),
	}
	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "build_info",
		Help:      "Always 1; the labels carry the relay and Go versions.",
	}, []string{"version", "go_version"})
	buildInfo.WithLabelValues(version, runtime.Version()).Set(1)

	m.registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.requestsTotal, m.requestDuration, m.inboundAuthFailures,
		m.tokenRenewals, m.idpRequestDuration, m.secretRefreshes, buildInfo,
	)
	return m
}

// registerTokenExpiry exports the time left on the current access token.
// It is only registered when the relay manages tokens itself (no
// relay.fixedtoken).
func (m *metrics) registerTokenExpiry(tokens *token.Manager) {
	m.registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "token_expires_in_seconds",
		Help:      "Seconds until the current access token expires (negative once expired, 0 before the first token). Includes the token.expiry_buffer safety margin.",
	}, func() float64 {
		tok := tokens.Current()
		if tok == nil {
			return 0
		}
		return time.Until(tok.ExpiresAt).Seconds()
	}))
}

// handler serves the registry in the Prometheus exposition format.
func (m *metrics) handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// observeRequest records a finished relayed request.
func (m *metrics) observeRequest(status int, upstreamHost string, elapsed time.Duration) {
	m.requestsTotal.WithLabelValues(strconv.Itoa(status), upstreamHost).Inc()
	m.requestDuration.WithLabelValues(upstreamHost).Observe(elapsed.Seconds())
}

// ObserveRenewal records the outcome of one login or refresh request.
func (m *metrics) ObserveRenewal(kind string, err error) {
	result := "success"
	if err != nil {
		result = "failure"
	}
	m.tokenRenewals.WithLabelValues(kind, result).Inc()
}

// ObserveIdPRequest records how long a token endpoint request took.
func (m *metrics) ObserveIdPRequest(kind string, elapsed time.Duration) {
	m.idpRequestDuration.WithLabelValues(kind).Observe(elapsed.Seconds())
}

// registerCertificate exports when the relay's TLS certificate expires. It
// is only registered when TLS is enabled.
func (m *metrics) registerCertificate(r *certReloader) {
	m.registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "tls_certificate_expiry_timestamp_seconds",
		Help:      "Unix time when the relay port's TLS certificate expires.",
	}, func() float64 { return float64(r.notAfter().Unix()) }))
}

// registerSecrets exports when secrets were last resolved. It is only
// registered when secrets managers are configured.
func (m *metrics) registerSecrets() {
	m.registry.MustRegister(m.secretsLastRefresh)
	m.secretsLastRefresh.SetToCurrentTime()
}

// observeSecretRefresh records the outcome of one secret re-fetch.
func (m *metrics) observeSecretRefresh(err error) {
	if err != nil {
		m.secretRefreshes.WithLabelValues("failure").Inc()
		return
	}
	m.secretRefreshes.WithLabelValues("success").Inc()
	m.secretsLastRefresh.SetToCurrentTime()
}
