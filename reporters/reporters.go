package reporters

import (
	"fmt"

	"github.com/spf13/viper"
	"golang.org/x/exp/slog"

	. "github.com/sgargan/cert-scanner-darkly/types"
)

var factories = map[string]ReporterFactory{"logging": loggingReporter, "metrics": metricsReporter}

func CreateReporters() (Reporters, error) {
	reporters := make(Reporters, 0)
	for name, reporterFactory := range factories {
		if v, err := getReporter(name, reporterFactory); err != nil {
			return nil, err
		} else if v != nil {
			reporters = append(reporters, v)
		}
	}
	slog.Debug("created all reporters", "count", len(reporters))
	return reporters, nil
}

func loggingReporter() (Reporter, error) {
	return CreateLoggingReporterWithPath(viper.GetString("reporters.logging.file"))
}

func metricsReporter() (Reporter, error) {
	return CreateMetricsReporter()
}

func getReporter(name string, factory ReporterFactory) (reporter Reporter, err error) {
	if viper.GetBool(fmt.Sprintf("reporters.%s.enabled", name)) {
		reporter, err = factory()
		slog.Debug("created reporter", "type", name)
	}
	return
}
