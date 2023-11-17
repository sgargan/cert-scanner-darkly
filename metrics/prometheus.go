package metrics

import (
	"fmt"
	"net"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sgargan/cert-scanner-darkly/config"
	"github.com/spf13/viper"
)

var (
	serverStarted bool = false
	millisBuckets      = []float64{1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000}
	validations   *prometheus.CounterVec
	latencies     *prometheus.HistogramVec
)

func Timing(millis float64, labels map[string]string) {
	latencies.With(labels).Observe(millis)
}

func Validation(labels map[string]string) {
	validations.With(labels).Inc()
}

func ConfigureMetrics(mux *http.ServeMux) error {
	registry := prometheus.NewRegistry()
	validations = createValidationCounter()

	registry.Register(validations)
	registry.Register(latencies)
	mux.Handle("/metrics", promhttp.HandlerFor(
		registry,
		promhttp.HandlerOpts{
			Registry:          registry,
			EnableOpenMetrics: true,
		}),
	)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", viper.GetInt(config.ConfigMetricsPort)))
	if err != nil {
		return err
	}
	go http.Serve(listener, mux)
	return nil
}

func createLatenciesHistogram() *prometheus.HistogramVec {
	return prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "scan_duration_millis",
		Help:    "A histogram of time taken to connect and retrieve tls state information from discovered endpoints.",
		Buckets: millisBuckets,
	}, []string{"source", "sourceType", "success"})
}

func createValidationCounter() *prometheus.CounterVec {
	return prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "scan_validations",
		Help: "A counter tracking scan validation results",
	}, []string{"type", "source", "sourceType", "success", "id", "common_name"})
}
