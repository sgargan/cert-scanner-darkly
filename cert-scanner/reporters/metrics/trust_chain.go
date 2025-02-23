package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/spf13/viper"
)

var (
	TrustChainLabelKeys = []string{
		"address", "source", "source_type", "failed", "type",
		"subject_cn", "issuer_cn", "authority_key_id",
	}

	TrustChainValidationsCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "cert_scanner",
		Name:      "trust_chain_validations_total",
		Help:      "counts the results of trust chain validations",
	}, TrustChainLabelKeys)
)

func CreateTrustChainReporter() (Reporter, error) {
	return &CounterReporter{
		counter:           TrustChainValidationsCounter,
		ignoreResultTypes: viper.GetStringSlice("validations.trust_chain.ignore"),
		requiredLabels:    TrustChainLabelKeys,
		validationType:    "trust_chain",
	}, nil
}
