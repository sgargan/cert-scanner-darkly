package metrics

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sgargan/cert-scanner-darkly/config"
	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/sgargan/cert-scanner-darkly/utils"
	"github.com/spf13/viper"
)

var (
	TLSVersionCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "cert_scanner",
		Name:      "tls_version_total",
		Help:      "counts of each tls version detected",
	}, []string{
		"source",
		"source_type",
		"name",
		"success",
		"version",
		"cypher",
	})

	ScanDurationHistogram = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "cert_scanner",
		Name:      "scan_duration_milliseconds",
		Help:      "duration of scans in milliseconds",
		Buckets:   []float64{5, 10, 50, 75, 100, 250, 500, 750, 1000, 1500},
	}, []string{
		"source",
		"source_type",
		"success",
	})
)

// ScanStatsReporter tracks metrics about each scan,
type ScanStatsReporter struct {
	tlsVersionCounter     CounterVec
	scanDurationHistogram HistogramVec
}

func (r *ScanStatsReporter) Report(ctx context.Context, scan *TargetScan) {
	for _, scanResult := range scan.Results {
		source := scan.Target.Source
		sourceType := scan.Target.SourceType
		name := scan.Target.Name
		version := "n/a"
		cypher := "n/a"
		success := "false"

		if !scanResult.Failed {
			success = "true"
		}

		if scanResult.State != nil {
			version = utils.ToVersion(int(scanResult.State.Version))
			cypher = scanResult.Cipher.Name
		}

		r.scanDurationHistogram.WithLabelValues(source, sourceType, success).Observe(float64(scan.Duration.Milliseconds()))

		onlySuccessful := viper.GetBool(config.ReportersScanStatsOnlySuccessful)
		if (onlySuccessful && !scanResult.Failed) || !onlySuccessful {
			r.tlsVersionCounter.WithLabelValues(source, sourceType, name, success, version, cypher).Inc()
		}
	}
}

func CreateScanStatsReporter() (Reporter, error) {
	return &ScanStatsReporter{
		TLSVersionCounter,
		ScanDurationHistogram,
	}, nil
}
