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
	ConfigMetricsPort                = "metrics.port"
	DiscoveryK8sSource               = "discovery.kubernetes.source"
	DiscoveryK8sNamespace            = "discovery.kubernetes.namespace"
	DiscoveryK8sKeys                 = "discovery.kubernetes.keys"
	ValidationsExpiryWindow          = "validations.expiry.warning_window"
	ValidationsTrustChainCACertPaths = "validations.trust-chain.ca_paths"
	ValidationsTLSMinVersion         = "validations.tls_version.min_version"
	Interval                         = "interval"
	Timeout                          = "timeout"
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

	if err := checkDuration(Interval); err != nil {
		return err
	}
	if err := checkDuration(Timeout); err != nil {
		return err
	}

	return nil
}

func setDefaults() {
	viper.Set("processors.tls-state.enabled", true)
	viper.SetDefault(ValidationsExpiryWindow, "168h")
	viper.SetDefault(ValidationsTrustChainCACertPaths, []string{})
	viper.SetDefault(ValidationsTLSMinVersion, "1.2")
	viper.SetDefault("reporters.logging.enabled", true)
	viper.SetDefault("reporters.metrics.enabled", true)
}

func checkDuration(key string) error {
	var err error
	durationAsString := viper.GetString(key)
	duration := time.Duration(0)
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
