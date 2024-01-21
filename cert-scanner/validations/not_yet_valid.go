package validations

import (
	"fmt"
	"time"

	. "github.com/sgargan/cert-scanner-darkly/types"
)

type BeforeValidation struct{}

type BeforeValidationError struct {
	ScanError
	untilValid time.Duration
	notBefore  time.Time
	result     *ScanResult
}

func (e *BeforeValidationError) Error() string {
	return fmt.Sprintf("cert will not be valid for %s, until %s", e.untilValid.String(),
		e.notBefore.Format(time.RFC822))
}

func (e *BeforeValidationError) Labels() map[string]string {
	labels := e.result.Labels()
	labels["type"] = "before"
	labels["until_valid"] = e.untilValid.String()
	labels["not_before"] = fmt.Sprintf("%d", e.notBefore.UnixMilli())
	return labels
}

func CreateBeforeValidation() *BeforeValidation {
	return &BeforeValidation{}
}

// Validate will examine each cert in a scan result and check that it's not within the
// configured time warning window before Before. If the cert will expire in the next 7 days
// this validation will fail and raise an error.
func (v *BeforeValidation) Validate(scan *TargetScan) ScanError {
	result := scan.Results[0]
	for _, cert := range result.State.PeerCertificates {
		untilValid := time.Until(cert.NotBefore)
		if untilValid > 0 {
			return &BeforeValidationError{
				untilValid: untilValid,
				notBefore:  cert.NotBefore,
			}
		}
	}
	return nil
}
