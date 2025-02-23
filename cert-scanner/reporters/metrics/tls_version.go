package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/spf13/viper"
)

var (
	TLSVersionLabelKeys = []string{
		"address", "source", "source_type", "failed", "type",
		"detected_version", "min_version",
	}

	TLSVersionValidationsCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "cert_scanner",
		Name:      "tls_version_validations_total",
		Help:      "counts the results of tls version validations",
	}, TLSVersionLabelKeys)
)

func CreateTLSVersionReporter() (Reporter, error) {
	return &CounterReporter{
		counter:           TLSVersionValidationsCounter,
		ignoreResultTypes: viper.GetStringSlice("validations.tls_version.ignore"),
		requiredLabels:    TLSVersionLabelKeys,
		validationType:    "tls_version",
	}, nil
}
