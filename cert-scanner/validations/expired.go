package validations

import (
	"fmt"
	"time"

	. "github.com/sgargan/cert-scanner-darkly/types"
	"golang.org/x/exp/slog"
)

type ExpiryValidation struct {
	warningDuration time.Duration
}

type ExpiryValidationError struct {
	warningDuration time.Duration
	notAfter        time.Time
	result          *ScanResult
}

func CreateExpiryValidationError(warningDuration time.Duration, notAfter time.Time, result *ScanResult) *ExpiryValidationError {
	return &ExpiryValidationError{
		result:          result,
		warningDuration: warningDuration,
		notAfter:        notAfter,
	}
}

func (e *ExpiryValidationError) Result() *ScanResult {
	return e.result
}

func (e *ExpiryValidationError) Error() string {
	return fmt.Sprintf("cert will expire in less than %s on %s", e.warningDuration.String(), e.notAfter.Format(time.RFC822))
}

func (e *ExpiryValidationError) Labels() map[string]string {
	labels := e.result.Labels()
	labels["type"] = "expiry"
	labels["warning_duration"] = e.warningDuration.String()
	labels["not_after"] = fmt.Sprintf("%d", e.notAfter.UnixMilli())
	labels["not_after_date"] = e.notAfter.Format(time.RFC3339)

	return labels
}

// CreateExpiryValidation with the given warning duration
func CreateExpiryValidation(warningDuration time.Duration) *ExpiryValidation {
	return &ExpiryValidation{warningDuration: warningDuration}
}

// Validate will examine the cert from the first successful ScanResult in a TargetScan
// and check that it's not within the configured time warning window before expiry. If the cert
// expiry falls in the the warning window, this validation will fail and raise a validation error
func (v *ExpiryValidation) Validate(scan *TargetScan) ScanError {
	slog.Debug("validating cert of target will not expire soon", "target", scan.Target.Name, "warning_duration", v.warningDuration.String())
	result := scan.FirstSuccessful
	for _, cert := range result.State.PeerCertificates {
		if time.Until(cert.NotAfter) < v.warningDuration {
			return CreateExpiryValidationError(v.warningDuration, cert.NotAfter, result)
		}
	}
	return nil
}
