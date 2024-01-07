package reporters

import (
	"context"
	"fmt"
	"os"
	"time"

	. "github.com/sgargan/cert-scanner-darkly/types"
	"golang.org/x/exp/slog"
)

type LoggingReporter struct {
	logger  *slog.Logger
	logFile *os.File
}

func CreateLoggingReporterWithPath(logPath string) (*LoggingReporter, error) {
	logFile := os.Stdout
	if logPath != "" {
		if f, err := os.OpenFile(logPath, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666); err != nil {
			return nil, fmt.Errorf("error opening logfile %s - %v", logPath, err)
		} else {
			logFile = f
		}
	}
	return CreateLoggingReporter(logFile)
}

func CreateLoggingReporter(logFile *os.File) (*LoggingReporter, error) {
	return &LoggingReporter{
		logFile: logFile,
		logger:  slog.New(slog.NewJSONHandler(logFile, &slog.HandlerOptions{Level: slog.LevelInfo})),
	}, nil
}

func (l *LoggingReporter) Report(ctx context.Context, result *CertScanResult) {
	if result != nil && result.Target != nil {
		labels := result.Labels()
		labels["duration"] = fmt.Sprintf("%d", result.Duration*time.Millisecond)
		labels["digest"] = result.Digest(labels)
		l.logger.Info("duration", labelsToList(labels)...)

		labels = result.Labels()
		for _, err := range result.Errors {
			labels := getCertificateLabels(result)
			for k, v := range err.Labels() {
				labels[k] = v
			}
			labels["digest"] = result.Digest(labels)
			l.logger.Info("violation", labelsToList(labels)...)
		}
	}
}

func (l *LoggingReporter) Close() {
	if l.logFile != nil {
		l.logFile.Close()
	}
}

func labelsToList(labels map[string]string) []interface{} {
	asList := make([]interface{}, 0)
	for k, v := range labels {
		asList = append(asList, k, v)
	}
	return asList
}
