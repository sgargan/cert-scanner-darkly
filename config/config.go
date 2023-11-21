package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

const (
	ValidationsExpiryWindow          = "validations.expiry.warning_window"
	ValidationsTrustChainCACertPaths = "validations.trust-chain.ca_paths"
	ValidationsTLSMinVersion         = "validations.tls_version.min_version"
	DiscoveryK8sSource               = "discovery.kubernetes.source"
	DiscoveryK8sNamespace            = "discovery.kubernetes.namespace"
	DiscoveryK8sKeys                 = "discovery.kubernetes.keys"
	ConfigMetricsPort                = "metrics.port"
)

// LoadConfiguration loads config from the configured file name into viper
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
	return nil
}

func setDefaults() {

	viper.SetDefault(ValidationsExpiryWindow, "168h")
	viper.SetDefault(ValidationsTrustChainCACertPaths, []string{"./certs/ca_chain.pem"})
	viper.SetDefault(ValidationsTLSMinVersion, "1.2")
	viper.SetDefault("reporters.logging.enabled", true)
	viper.SetDefault("reporters.metrics.enabled", true)
}

func determineConfigFilename() string {
	// this was set early to allow it to be read
	configFileName := viper.GetString("config")
	viper.SetConfigFile(configFileName)
	return configFileName
}
