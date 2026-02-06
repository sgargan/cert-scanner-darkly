package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
	"golang.org/x/exp/slog"
)

const (
	CanaryPort                       = "canary.port"
	MetricsPort                      = "metrics.port"
	MetricsEnabled                   = "metrics.enabled"
	DiscoveryK8sSource               = "discovery.kubernetes.source"
	DiscoveryK8sNamespace            = "discovery.kubernetes.namespace"
	DiscoveryK8sIgnorePatterns       = "discovery.kubernetes.ignore_pods"
	DiscoveryK8sIgnoreContainers     = "discovery.kubernetes.ignore_containers"
	DiscoveryK8sKeys                 = "discovery.kubernetes.keys"
	DiscoveryK8sMatchCIDR            = "discovery.kubernetes.match_cidr"
	DiscoveryFilePaths               = "discovery.files.paths"
	ProcessorsTlsEnabled             = "processors.tls-state.enabled"
	ValidationsExpiryWindow          = "validations.expiry.warning_window"
	ValidationsTrustChainCACertPaths = "validations.trust_chain.ca_paths"
	ValidationsTrustChainSystemRoots = "validations.trust_chain.use_system_roots"
	ValidationsNotYetValidEnabled    = "validations.not_yet_valid.enabled"
	ValidationsTLSMinVersion         = "validations.tls_version.min_version"
	ReportersMetricsExpiry           = "reporters.metrics.expiry"
	ReportersMetricsNotYetValid      = "reporters.metrics.not_yet_valid"
	ReportersMetricsTLSVersion       = "reporters.metrics.tls_version"
	ReportersMetricsTrustChain       = "reporters.metrics.expiry"
	ReportersLoggingEnabled          = "reporters.logging.enabled"
	ReportersScanStatsOnlySuccessful = "reporters.scan_stats.only_successful"
	ReportersMetricsEnabled          = "metrics.enabled"
	Interval                         = "scan.interval"
	Timeout                          = "scan.timeout"
	Repeated                         = "scan.repeated"
)

// LoadConfiguration loads and verifies configuration into viper.
func LoadConfiguration() error {
	configFile := determineConfigFilename()
	setDefaults()
	viper.AddConfigPath(".")
	viper.SetEnvPrefix("CERT_SCAN")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("error loading config file %s: %v", configFile, err)
	}

	configureLogging()

	if err := checkDuration(Interval, time.Duration(15*time.Minute)); err != nil {
		return err
	}
	if err := checkDuration(Timeout, time.Duration(15*time.Minute)); err != nil {
		return err
	}

	if viper.GetDuration("reporters.metrics.expiry") == 0 {
		viper.Set("reporters.metrics.expiry", viper.GetDuration(Interval)*2)
	}

	return nil
}

func setDefaults() {
	viper.Set(ProcessorsTlsEnabled, true)
	viper.SetDefault(ValidationsExpiryWindow, "168h")
	viper.SetDefault(ValidationsTrustChainCACertPaths, []string{})
	viper.SetDefault(ValidationsTLSMinVersion, "1.2")
	viper.SetDefault(ValidationsTrustChainCACertPaths, "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	viper.SetDefault(ValidationsNotYetValidEnabled, true)

	viper.SetDefault(ReportersLoggingEnabled, true)
	viper.SetDefault(ReportersMetricsEnabled, true)
}

func checkDuration(key string, duration time.Duration) error {
	var err error
	durationAsString := viper.GetString(key)
	if durationAsString != "" {
		if duration, err = time.ParseDuration(durationAsString); err != nil {
			return fmt.Errorf("duration %s of %s could not be parsed %s", key, durationAsString, err)
		}
	}
	viper.Set(key, duration)
	return nil
}

func determineConfigFilename() string {
	// this was set early to allow it to be read
	configFileName := viper.GetString("config")
	viper.SetConfigFile(configFileName)
	return configFileName
}

func configureLogging() {
	level := &slog.LevelVar{}
	level.Set(slog.LevelInfo)
	if viper.GetBool("debug") {
		level.Set(slog.LevelDebug)
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})))
}
