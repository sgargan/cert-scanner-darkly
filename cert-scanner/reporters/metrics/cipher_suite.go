package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/spf13/viper"
)

var (
	CipherSuiteLabelKeys = []string{
		"address", "source", "source_type", "failed", "type", "detected_cipher",
	}

	InvalidCipherSuiteCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "cert_scanner",
		Name:      "invalid_cipher_suite_total",
		Help:      "counts the number of times an invalid cipher suite was detected",
	}, CipherSuiteLabelKeys)
)

func CreateCipherSuiteReporter() (Reporter, error) {
	return &CounterReporter{
		counter:           InvalidCipherSuiteCounter,
		ignoreResultTypes: viper.GetStringSlice("validations.cipher_suite.ignore"),
		validationType:    "cipher_suite",
		requiredLabels:    CipherSuiteLabelKeys,
	}, nil
}
