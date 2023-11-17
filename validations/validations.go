package validations

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
	"golang.org/x/exp/slog"

	"github.com/sgargan/cert-scanner-darkly/config"
	. "github.com/sgargan/cert-scanner-darkly/types"
)

const (
	DefaultWarningDuration = time.Duration(14 * 24 * time.Hour)
)

var factories = map[string]ValidationFactory{"expiry": expiryValidation, "before": beforeValidation, "tls-version": tlsVersionValidation, "trust-chain": trustChainValidation}

func CreateValidations() (Validations, error) {
	validations := make(Validations, 0)
	for name, validationFactory := range factories {
		if v, err := getValidation(name, validationFactory); err != nil {
			return nil, err
		} else if v != nil {
			validations = append(validations, v)
		}
	}
	slog.Debug("created all validations", "count", len(validations))
	return validations, nil
}

func expiryValidation() (Validation, error) {
	warning := DefaultWarningDuration
	duration := viper.GetString(config.ConfigExpiryWindow)
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
	caCertPaths := viper.GetStringSlice(config.ConfigTrustChainCACertPaths)
	return CreateTrustChainValidationWithPaths(caCertPaths)
}

func tlsVersionValidation() (Validation, error) {
	return CreateTLSVersionValidation(viper.GetString(config.ConfigTLSMinVersion))
}

func getValidation(name string, factory ValidationFactory) (validation Validation, err error) {
	if viper.GetBool(fmt.Sprintf("validations.%s.enabled", name)) {
		validation, err = factory()
		slog.Debug("created validation", "type", name)
	}
	return
}
