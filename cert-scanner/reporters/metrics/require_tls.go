package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/spf13/viper"
)

var (
	RequireTLSLabelKeys = []string{
		"address", "source", "source_type", "failed", "type", "target_pod", "target_namespace",
	}

	RequireTLSValidationsCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "cert_scanner",
		Name:      "require_tls_validations_total",
		Help:      "counts the results required tls validations",
	}, RequireTLSLabelKeys)
)

func CreateRequireTLSReporter() (Reporter, error) {
	return &CounterReporter{
		counter:           RequireTLSValidationsCounter,
		ignoreResultTypes: viper.GetStringSlice("validations.require_tls.ignore"),
		requiredLabels:    RequireTLSLabelKeys,
		validationType:    "require_tls",
	}, nil
}
