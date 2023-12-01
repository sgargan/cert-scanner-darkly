package reporters

import (
	"github.com/spf13/viper"

	"github.com/sgargan/cert-scanner-darkly/config"
	. "github.com/sgargan/cert-scanner-darkly/types"
)

var factories = map[string]Factory[Reporter]{"logging": loggingReporter, "metrics": metricsReporter}

func CreateReporters() (Reporters, error) {
	return config.CreateConfigured[Reporter]("reporters", factories)
}

func loggingReporter() (Reporter, error) {
	return CreateLoggingReporterWithPath(viper.GetString("reporters.logging.file"))
}

func metricsReporter() (Reporter, error) {
	return CreateMetricsReporter()
}
