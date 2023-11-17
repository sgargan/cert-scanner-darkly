package metrics

import (
	"time"
)

const (
	testPrefix            = "cert_scanner_"
	testThresholdInterval = time.Second

	newLine = "\n"
	space   = " "
)

// func (me *PrometheusMetrics) stop() error {
// 	var err error
// 	if me.thresholds != nil {
// 		me.thresholds.Stop()
// 	}
// 	if me.listener != nil {
// 		err = me.listener.Close()
// 		me.listener = nil
// 	}
// 	return err
// }

// type PrometheusReporterTests struct {
// 	suite.Suite
// }

// func TestPrometheusReporter(t *testing.T) {
// 	suite.Run(t, &PrometheusReporterTests{})
// }

// func (assert *PrometheusReporterTests) TestPortOpened() {
// 	assert.withServer(testThresholdKey, testThresholdInterval, false, func(metricsServer *PrometheusMetrics) {
// 		url := fmt.Sprintf("http://%s/metrics", metricsServer.listenerAddress)
// 		response, statusCode, err := requests.Get(url, nil)
// 		assert.NoError(err)
// 		assert.Equal(http.StatusOK, statusCode)
// 		assert.NotEmpty(response)
// 	})
// }

// func (assert *PrometheusReporterTests) TestPprofEnabled() {
// 	assert.withServer(testThresholdKey, testThresholdInterval, true, func(metricsServer *PrometheusMetrics, mcs *consulMock.MockConsulServer) {
// 		for path := range pprofFuncs {
// 			url := fmt.Sprintf("http://%s%s?seconds=1", metricsServer.listenerAddress, path)
// 			_, statusCode, err := requests.Get(url, nil)
// 			assert.NoError(err)
// 			assert.Equal(200, statusCode)
// 		}
// 	})
// }

// func (assert *PrometheusReporterTests) TestTiming() {
// 	assert.withServer("", testThresholdInterval, false, func(metricsServer *PrometheusMetrics, mcs *consulMock.MockConsulServer) {
// 		testSource, testHost, testFqdn, testService := "tests", "host", "host.dc.domain.net", "my-service"
// 		testLabels := fmt.Sprintf(
// 			"ping_source=\"%s\",stargate_fqdn=\"%s\",stargate_host=\"%s\",stargate_service=\"%s\"",
// 			testSource, testFqdn, testHost, testService,
// 		)
// 		testCountMetricName := "stargate_latencies_millis_count"
// 		testFullMetricName := fmt.Sprintf("%s{%s}", testCountMetricName, testLabels)

// 		testValues := []float64{123.456, 234.567, 345.678}
// 		for _, testValue := range testValues {
// 			metricsServer.Timing(testValue, testFqdn, testHost, testService)
// 			time.Sleep(200 * time.Millisecond)
// 		}

// 		metrics := assert.getMetrics(metricsServer, testCountMetricName)
// 		fmt.Printf("Timing metrics:\n%v", metrics)
// 		assert.Contains(metrics, testFullMetricName)
// 		assert.Equal(float64(len(testValues)), metrics[testFullMetricName])
// 	})
// }

// func (assert *PrometheusReporterTests) TestThresholdsRefreshed() {
// 	assert.withServer(testThresholdKey, testThresholdInterval, false, func(metricsServer *PrometheusMetrics, mcs *consulMock.MockConsulServer) {
// 		customThresholds := []byte(`# comments
//         warning:
//           0.50: 111
//           0.95: 222
//         critical:
//           0.50: 333
//           0.95: 444
//         `)

// 		err := mcs.ImportKV(testThresholdKey, customThresholds)
// 		assert.NoError(err)

// 		time.Sleep(2 * time.Second)
// 		thresholdMetrics := assert.getMetrics(metricsServer, "stargate_latency_threshold_millis")
// 		fmt.Printf("Threshold Metrics:\n%v", thresholdMetrics)

// 		for key, value := range map[string]float64{
// 			"level=\"warning\",percentile=\"0.50\"":  111,
// 			"level=\"warning\",percentile=\"0.95\"":  222,
// 			"level=\"critical\",percentile=\"0.50\"": 333,
// 			"level=\"critical\",percentile=\"0.95\"": 444,
// 		} {
// 			metricName := fmt.Sprintf("stargate_latency_threshold_millis{%s}", key)
// 			metricValue, found := thresholdMetrics[metricName]
// 			assert.True(found)
// 			assert.Equal(value, metricValue)
// 		}
// 	})
// }

// func (assert *PrometheusReporterTests) withServer(thresholdsKey string, thresholdsInterval time.Duration, enablePprof bool, handler func(*PrometheusMetrics, *consulMock.MockConsulServer)) {
// 	consulMock.WithServer(func(consulServer *consulMock.MockConsulServer) {
// 		port, err := testUtils.GetFreePort()
// 		assert.NoError(err)

// 		serverAddress := fmt.Sprintf("127.0.0.1:%d", port)
// 		metricsServer := NewMetrics(testNamespace, serverAddress, thresholdsKey, "tests", enablePprof)
// 		assert.NotNil(metricsServer)

// 		defer func() {
// 			assert.NoError(metricsServer.stop())
// 			serverStarted = false
// 		}()

// 		time.Sleep(time.Second)
// 		handler(metricsServer, consulServer)
// 	})
// }

// func (assert *PrometheusReporterTests) getMetrics(metricsServer *PrometheusMetrics, pattern string) map[string]float64 {
// 	url := fmt.Sprintf("http://%s/metrics", metricsServer.listenerAddress)
// 	response, statusCode, err := requests.Get(url, nil)
// 	assert.NoError(err)
// 	assert.Equal(http.StatusOK, statusCode)

// 	results := map[string]float64{}
// 	for _, line := range strings.Split(string(response), newLine) {
// 		if strings.HasPrefix(line, testPrefix) && strings.Contains(line, pattern) {
// 			parts := strings.Split(line, space)
// 			assert.Equal(2, len(parts))

// 			value, err := strconv.ParseFloat(parts[1], 64)
// 			assert.NoError(err)

// 			results[parts[0]] = value
// 		}
// 	}
// 	fmt.Printf("getMetrics(%s): %v\n", pattern, results)
// 	return results
// }
