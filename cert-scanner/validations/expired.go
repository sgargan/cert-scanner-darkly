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
	if time.Now().After(e.notAfter) {
		return fmt.Sprintf("cert expired on %s", e.notAfter.Format(time.RFC822))
	}
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
// and check that it is not already expired and not within the configured warning window
// before expiry. If either condition is met, this validation will fail.
func (v *ExpiryValidation) Validate(scan *TargetScan) ScanError {
	slog.Debug("validating cert of target will not expire soon", "target", scan.Target.Name, "warning_duration", v.warningDuration.String())
	result := scan.ResultWithCertificates()
	if result == nil {
		slog.Debug("no peer certificates found in scan result", "target", scan.Target.Name)
		return nil
	}

	now := time.Now()
	for _, cert := range result.State.PeerCertificates {
		if certExpiredOrExpiringSoon(now, cert.NotAfter, v.warningDuration) {
			return CreateExpiryValidationError(v.warningDuration, cert.NotAfter, result)
		}
	}
	return nil
}

func certExpiredOrExpiringSoon(now, notAfter time.Time, warningDuration time.Duration) bool {
	if now.After(notAfter) {
		return true
	}
	return notAfter.Sub(now) < warningDuration
}
