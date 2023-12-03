package metrics

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type MetricsServerTests struct {
	suite.Suite
	server *MetricsServer
}

func (t *MetricsServerTests) SetupSuite() {
	t.server = ConfigureMetrics(8888)
	t.NoError(t.server.Start())
}

func (t *MetricsServerTests) TearDownSuite() {
	t.server.Stop()
}

func (t *MetricsServerTests) TestTiming() {

	testCountMetricName := "cert_scanner_scan_duration"

	Timing(123.456, map[string]string{"foo": "bar", "bar": "baz"})
	time.Sleep(500 * time.Millisecond)
	Timing(234.567, map[string]string{"foo": "bar", "bar": "bing"})
	time.Sleep(500 * time.Millisecond)

	metrics := t.getMetrics(t.server, testCountMetricName)
	t.Contains(metrics, "cert_scanner_scan_duration_sum{bar=\"baz\",foo=\"bar\"}")
	t.Contains(metrics, "cert_scanner_scan_duration{bar=\"baz\",foo=\"bar\",quantile=\"0.5\"}")
	t.Contains(metrics, "cert_scanner_scan_duration{bar=\"baz\",foo=\"bar\",quantile=\"0.9\"}")
	t.Contains(metrics, "cert_scanner_scan_duration{bar=\"baz\",foo=\"bar\",quantile=\"0.99\"}")
	t.Equal(float64(1), metrics["cert_scanner_scan_duration_count{bar=\"baz\",foo=\"bar\"}"])
}

func (t *MetricsServerTests) TestValidation() {

	testCountMetricName := "cert_scanner_scan_validation"

	// for x := 0; x < 5; x++ {
	Validation(map[string]string{"foo": "bar", "status": "success"})
	time.Sleep(1000 * time.Millisecond)
	// }

	metrics := t.getMetrics(t.server, testCountMetricName)
	t.Contains(metrics, "cert_scanner_scan_validation{foo=\"bar\",status=\"success\"}")
}

func (t *MetricsServerTests) getMetrics(metricsServer *MetricsServer, pattern string) map[string]float64 {
	response, err := http.Get(fmt.Sprintf("http://:%d/metrics", metricsServer.port))
	if !t.NoError(err) {
		return nil
	}
	t.Equal(http.StatusOK, response.StatusCode)

	body, err := io.ReadAll(response.Body)
	t.NoError(err)
	results := map[string]float64{}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "cert_scanner_") && strings.Contains(line, pattern) {
			parts := strings.Split(line, " ")
			t.Equal(2, len(parts))

			value, err := strconv.ParseFloat(parts[1], 64)
			t.NoError(err)
			results[parts[0]] = value
		}
	}
	return results
}

func TestPrometheusReporter(t *testing.T) {
	suite.Run(t, &MetricsServerTests{})
}
