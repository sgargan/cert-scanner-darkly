package config

import (
	"os"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/suite"
)

type ConfigTests struct {
	suite.Suite
}

func (t *ConfigTests) TestLoadConfig() {
	yaml := `---
validations:
  expiry:
    warning_window: 72h
  tls_version:
    min_version: 1.3
  trust:
    ca:
       paths: 
       - /a/ca/path
       - /b/ca/path
       - /c/ca/path

reporters:
  logging:
    enabled: true
  metrics:
    enabled: true
`

	t.runTestCase("Full valid config", yaml)
	t.True(viper.GetBool("reporters.metrics.enabled"))
	t.True(viper.GetBool("reporters.logging.enabled"))
	t.Equal("1.3", viper.GetString("validations.tls_version.min_version"))
	t.Equal([]string{"/a/ca/path", "/b/ca/path", "/c/ca/path"},
		viper.GetStringSlice("validations.trust.ca.paths"))
	t.Equal(t.ParseDuration("72h"), viper.GetDuration("validations.expiry.warning_window"))
}

func (t *ConfigTests) TestLoadEmptyConfig() {
	t.runTestCase("empty config", "")
	t.True(viper.GetBool("reporters.metrics.enabled"))
	t.True(viper.GetBool("reporters.logging.enabled"))
	t.Equal("1.2", viper.GetString("validations.tls_version.min_version"))
	t.Equal(t.ParseDuration("168h"), viper.GetDuration("validations.expiry.warning_window"))
}

func (t *ConfigTests) TestNoConfig() {
	t.runTestCase("empty config", "")
	t.True(viper.GetBool("reporters.metrics.enabled"))
	t.True(viper.GetBool("reporters.logging.enabled"))
	t.Equal("1.2", viper.GetString("validations.tls_version.min_version"))
	t.Equal(t.ParseDuration("168h"), viper.GetDuration("validations.expiry.warning_window"))
}

func (t *ConfigTests) TestInvalidDurations() {
	t.Error(t.runTestCaseWithError("invalid interval", `scan:
    interval: not a duration
`))
	t.Error(t.runTestCaseWithError("invalid timeout", `scan:
	timeout: not a duration
`))
}

func (t *ConfigTests) TestConfigFileDoesNotExist() {
	viper.Set("config", "doesnotextist")
	t.Error(LoadConfiguration())
}

func (t *ConfigTests) runTestCase(name, yaml string) {
	t.NoError(t.runTestCaseWithError(name, yaml))
}

func (t *ConfigTests) runTestCaseWithError(name, yaml string) error {
	configFile, err := os.CreateTemp("/tmp", "certscan*.yml")
	t.NoError(err)
	_, err = configFile.WriteString(yaml)
	t.NoError(err)
	configFile.Close()

	viper.Set("config", configFile.Name())
	return LoadConfiguration()
}

func (t *ConfigTests) ParseDuration(duration string) time.Duration {
	d, err := time.ParseDuration(duration)
	t.NoError(err)
	return d
}

func TestConfigTests(t *testing.T) {
	suite.Run(t, &ConfigTests{})
}
