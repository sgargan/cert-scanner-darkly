package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/spf13/viper"
)

var (
	NotYetValidLabelKeys = []string{
		"address", "source", "source_type", "failed", "type",
		"until_valid", "not_before", "not_before_date",
	}

	NotYetValidValidationsCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "cert_scanner",
		Name:      "certificate_not_yet_valid_validations_total",
		Help:      "counts the results of certificate not yet valid validations",
	}, NotYetValidLabelKeys)
)

func CreateNotYetValidReporter() (Reporter, error) {
	return &CounterReporter{
		counter:           NotYetValidValidationsCounter,
		ignoreResultTypes: viper.GetStringSlice("validations.not_yet_valid.ignore"),
		validationType:    "not_yet_valid",
		requiredLabels:    NotYetValidLabelKeys,
	}, nil
}
