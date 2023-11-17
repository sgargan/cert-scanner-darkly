package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

const (
	ConfigExpiryWindow          = "validations.expiry.warning_window"
	ConfigTrustChainCACertPaths = "validations.trust-chain.ca_paths"
	ConfigTLSMinVersion         = "validations.tls_version.min_version"
	ConfigMetricsPort           = "metrics.port"
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

	viper.SetDefault(ConfigExpiryWindow, "168h")
	viper.SetDefault(ConfigTrustChainCACertPaths, []string{"./certs/ca_chain.pem"})
	viper.SetDefault(ConfigTLSMinVersion, "1.2")
	viper.SetDefault("reporters.logging.enabled", true)
	viper.SetDefault("reporters.metrics.enabled", true)
}

func determineConfigFilename() string {
	// this was set early to allow it to be read
	configFileName := viper.GetString("config")
	viper.SetConfigFile(configFileName)
	return configFileName
}
