package metrics

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/suite"
)

type MetricsServerTests struct {
	suite.Suite
	server *MetricsServer
}

func (t *MetricsServerTests) SetupSuite() {
	viper.Set("pprof", true)
	viper.Set("metrics.enabled", true)
	t.server = ConfigureMetrics(8889)
	t.NoError(t.server.Start())
}

func (t *MetricsServerTests) TearDownSuite() {
	t.server.Stop()
}

func (t *MetricsServerTests) TestMetrics() {
	response, err := http.Get(fmt.Sprintf("http://:%d/metrics", t.server.port))
	if t.NoError(err) {
		t.Equal(http.StatusOK, response.StatusCode)
	}
}

func (t *MetricsServerTests) TestHealth() {
	response, err := http.Get(fmt.Sprintf("http://:%d/health", t.server.port))
	if t.NoError(err) {
		t.Equal(http.StatusOK, response.StatusCode)
	}
}

func (t *MetricsServerTests) TestPProf() {
	response, err := http.Get(fmt.Sprintf("http://:%d/debug/pprof/cmdline", t.server.port))
	if t.NoError(err) {
		t.Equal(http.StatusOK, response.StatusCode)
	}
}

func TestPrometheusReporter(t *testing.T) {
	suite.Run(t, &MetricsServerTests{})
}
