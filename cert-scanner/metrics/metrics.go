package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sgargan/cert-scanner-darkly/config"
	"github.com/spf13/viper"
)

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
	if !viper.GetBool(config.MetricsEnabled) {
		return nil
	}
	mux := &http.ServeMux{}
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})

	if viper.GetBool("pprof") {
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
	}

	address := fmt.Sprintf(":%d", m.port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

	slog.Info("starting metrics server", "address", address)
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
