package metrics

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/hashicorp/go-metrics"
	"github.com/hashicorp/go-metrics/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	MetricsName = "cert_scanner"
)

var (
	millisBuckets = []float64{1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000}
	TimingMetric  = []string{"scan", "duration"}
)

func Timing(millis float64, labels map[string]string) {
	metrics.AddSampleWithLabels(TimingMetric, millis, toLabels(labels))
}

func Validation(labels map[string]string) {
	metrics.IncrCounterWithLabels(TimingMetric, toLabels(labels))
}

func toLabels(labels map[string]string) []metrics.Label {
	to := make([]metrics.Label, 0)
	for k, v := range labels {
		to = append(to, metrics.Label{Name: k, Value: v})
	}
	return to
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

	sink, err := prometheus.NewPrometheusSinkFrom(prometheus.PrometheusOpts{
		Name: MetricsName,
	})
	if err != nil {
		return fmt.Errorf("Error creating metrics: %v", err)
	}

	metrics.NewGlobal(metrics.DefaultConfig(MetricsName), sink)

	mux := &http.ServeMux{}
	mux.Handle("/metrics", promhttp.Handler())

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", m.port))
	if err != nil {
		return err
	}

	m.server = &http.Server{Handler: mux}
	go m.server.Serve(listener)
	return nil
}

func (m *MetricsServer) Stop() error {
	if m.server != nil {
		return m.server.Shutdown(context.Background())
	}
	return nil
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
