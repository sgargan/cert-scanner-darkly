package reporters

import (
	"github.com/spf13/viper"

	"github.com/sgargan/cert-scanner-darkly/config"
	"github.com/sgargan/cert-scanner-darkly/reporters/metrics"
	. "github.com/sgargan/cert-scanner-darkly/types"
)

var factories = map[string]Factory[Reporter]{
	"logging":       loggingReporter,
	"expiry":        metrics.CreateExpiryReporter,
	"not_yet_valid": metrics.CreateNotYetValidReporter,
	"tls_version":   metrics.CreateTLSVersionReporter,
	"trust_chain":   metrics.CreateTrustChainReporter,
}

func CreateReporters() (Reporters, error) {
	reporters, err := config.CreateConfigured[Reporter]("reporters", factories)
	if err != nil {
		return nil, err
	}
	reportersBasedOnEnabledValidations, err := config.CreateConfigured[Reporter]("validations", factories)
	if err != nil {
		return nil, err
	}
	return append(reporters, reportersBasedOnEnabledValidations...), nil
}

func loggingReporter() (Reporter, error) {
	return CreateLoggingReporterWithPath(viper.GetString("reporters.logging.file"))
}
