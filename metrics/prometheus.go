package metrics

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	millisBuckets = []float64{1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000}
	validations   *prometheus.CounterVec
	timings       *prometheus.HistogramVec
)

func Timing(millis float64, labels map[string]string) {
	timings.With(labels).Observe(millis)
}

func Validation(labels map[string]string) {
	validations.With(labels).Inc()
}

type MetricsServer struct {
	server *http.Server
	port   int
}

func ConfigureMetrics(port int) *MetricsServer {
	return &MetricsServer{
		port: port,
	}
}

func (m *MetricsServer) Start() error {
	registry := prometheus.NewRegistry()
	validations = createValidationCounter()
	timings = createLatenciesHistogram()

	registry.Register(validations)
	registry.Register(timings)
	mux := &http.ServeMux{}
	mux.Handle("/metrics", promhttp.HandlerFor(
		registry,
		promhttp.HandlerOpts{
			Registry:          registry,
			EnableOpenMetrics: true,
		}),
	)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", m.port))
	if err != nil {
		return err
	}

	m.server = &http.Server{Handler: mux}
	go m.server.Serve(listener)
	return nil
}

func (m *MetricsServer) Stop() error {
	return m.server.Shutdown(context.Background())
}

func createLatenciesHistogram() *prometheus.HistogramVec {
	return prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "scan_duration_millis",
		Help:    "A histogram of time taken to connect and retrieve tls state information from discovered endpoints.",
		Buckets: millisBuckets,
	}, []string{"source", "sourceType", "success", "type"})
}

func createValidationCounter() *prometheus.CounterVec {
	return prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "scan_validations",
		Help: "A counter tracking scan validation results",
	}, []string{"type", "source", "sourceType", "success", "id", "common_name"})
}
