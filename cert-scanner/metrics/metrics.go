package metrics

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"

	"github.com/hashicorp/go-metrics"
	"github.com/hashicorp/go-metrics/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	MetricsName = "cert_scanner"
)

var (
	TimingMetric     = []string{"scan", "duration"}
	ValidationMetric = []string{"scan", "validation"}
)

func Timing(millis float32, labels map[string]string) {
	metrics.AddSampleWithLabels(TimingMetric, millis, toLabels(labels))
}

func Validation(labels map[string]string) {
	metrics.IncrCounterWithLabels(ValidationMetric, 1, toLabels(labels))
}

func toLabels(labels map[string]string) []metrics.Label {
	to := make([]metrics.Label, 0)
	for k, v := range labels {
		to = append(to, metrics.Label{Name: k, Value: v})
	}
	return to
}

type MetricsServer struct {
	server  *http.Server
	metrics *metrics.Metrics
	port    int
}

func ConfigureMetrics(port int) *MetricsServer {
	return &MetricsServer{
		port: port,
	}
}

func (m *MetricsServer) Start() error {
	// potentially we can support other metrics sinks via config
	sink, err := prometheus.NewPrometheusSinkFrom(prometheus.PrometheusOpts{
		Name: MetricsName,
	})
	if err != nil {
		return fmt.Errorf("error creating metrics sink: %v", err)
	}

	if m.metrics, err = metrics.NewGlobal(metrics.DefaultConfig(MetricsName), sink); err != nil {
		return fmt.Errorf("error creating metrics instance: %v", err)
	}

	mux := &http.ServeMux{}
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})

	for path, handler := range map[string]func(http.ResponseWriter, *http.Request){
		"/debug/pprof/":        pprof.Index,
		"/debug/pprof/heap":    pprof.Index,
		"/debug/pprof/cmdline": pprof.Cmdline,
		"/debug/pprof/profile": pprof.Profile,
		"/debug/pprof/symbol":  pprof.Symbol,
		"/debug/pprof/trace":   pprof.Trace,
	} {
		mux.HandleFunc(path, handler)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", m.port))
	if err != nil {
		return err
	}

	m.server = &http.Server{Handler: mux}
	go m.server.Serve(listener)
	return nil
}

func (m *MetricsServer) Stop() error {
	if m.metrics != nil {
		m.metrics.Shutdown()
	}
	if m.server != nil {

		return m.server.Shutdown(context.Background())
	}
	return nil
}
