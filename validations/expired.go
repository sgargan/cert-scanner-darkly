package validations

import (
	"fmt"
	"time"

	. "github.com/sgargan/cert-scanner-darkly/types"
)

type ExpiryValidation struct {
	warningDuration time.Duration
}

type ExpiryValidationError struct {
	warningDuration time.Duration
	notAfter        time.Time
}

func (e *ExpiryValidationError) Error() string {
	return fmt.Sprintf("cert will expire in less than %s on %s", e.warningDuration.String(), e.notAfter.Format(time.RFC822))
}

func (e *ExpiryValidationError) Labels() map[string]string {
	return map[string]string{
		"type":             "expiry",
		"warning_duration": e.warningDuration.String(),
		"not_after":        fmt.Sprintf("%d", e.notAfter.UnixMilli()),
	}
}

// CreateExpiryValidation with the given warning duration
func CreateExpiryValidation(warningDuration time.Duration) *ExpiryValidation {
	return &ExpiryValidation{warningDuration: warningDuration}
}

// Validate will examine each cert in a scan result and check that it's not within the
// configured time warning window before expiry. If the cert will expire in the next 7 days
// this validation will fail and raise an error.
func (v *ExpiryValidation) Validate(result *CertScanResult) ScanError {
	for _, cert := range result.State.PeerCertificates {
		if time.Until(cert.NotAfter) < v.warningDuration {
			return &ExpiryValidationError{
				warningDuration: v.warningDuration,
				notAfter:        cert.NotAfter,
			}
		}
	}
	return nil
}
