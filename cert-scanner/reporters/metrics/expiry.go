package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/spf13/viper"
)

var (
	ExpiryLabelKeys = []string{
		"address", "source", "source_type", "failed", "type",
		"warning_duration", "not_after", "not_after_date",
	}

	ExpiryValidationsCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "cert_scanner",
		Name:      "certificate_expiry_validations_total",
		Help:      "counts the results of certificate expiry validations",
	}, ExpiryLabelKeys)
)

func CreateExpiryReporter() (Reporter, error) {
	return &CounterReporter{
		counter:           ExpiryValidationsCounter,
		ignoreResultTypes: viper.GetStringSlice("validations.expiry.ignore"),
		requiredLabels:    ExpiryLabelKeys,
		validationType:    "expiry",
	}, nil
}
