package validations

import (
	"fmt"
	"time"

	"github.com/spf13/viper"

	"github.com/sgargan/cert-scanner-darkly/config"
	. "github.com/sgargan/cert-scanner-darkly/types"
)

const (
	DefaultWarningDuration = time.Duration(14 * 24 * time.Hour)
)

var factories = map[string]Factory[Validation]{
	"expiry":        expiryValidation,
	"not_yet_valid": beforeValidation,
	"tls_version":   tlsVersionValidation,
	"trust_chain":   trustChainValidation,
}

func CreateValidations() (Validations, error) {
	return config.CreateConfigured[Validation]("validations", factories)
}

func expiryValidation() (Validation, error) {
	warning := DefaultWarningDuration
	duration := viper.GetString(config.ValidationsExpiryWindow)
	if duration != "" {
		if parsed, err := time.ParseDuration(duration); err != nil {
			return nil, fmt.Errorf("error parsing expiry warning duration from %s", duration)
		} else {
			warning = parsed
		}
	}
	return CreateExpiryValidation(warning), nil
}

func beforeValidation() (Validation, error) {
	return CreateBeforeValidation(), nil
}

func trustChainValidation() (Validation, error) {
	caCertPaths := viper.GetStringSlice(config.ValidationsTrustChainCACertPaths)
	return CreateTrustChainValidationWithPaths(caCertPaths)
}

func tlsVersionValidation() (Validation, error) {
	return CreateTLSVersionValidation(viper.GetString(config.ValidationsTLSMinVersion))
}
