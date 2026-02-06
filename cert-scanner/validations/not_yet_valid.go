package validations

import (
	"fmt"
	"time"

	. "github.com/sgargan/cert-scanner-darkly/types"
	"golang.org/x/exp/slog"
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

func (e *BeforeValidationError) Result() *ScanResult {
	return e.result
}

func (e *BeforeValidationError) Labels() map[string]string {
	labels := e.result.Labels()
	labels["type"] = "before"
	labels["until_valid"] = e.untilValid.String()
	labels["not_before"] = fmt.Sprintf("%d", e.notBefore.UnixMilli())
	labels["not_before_date"] = e.notBefore.Format(time.RFC3339)
	return labels
}

func CreateBeforeValidation() *BeforeValidation {
	return &BeforeValidation{}
}

// Validate will examine each cert in a scan result raise a violation
// if the cert will not become valid until some time in the future
func (v *BeforeValidation) Validate(scan *TargetScan) ScanError {
	slog.Debug("validating cert of taget is currently valid", "target", scan.Target.Name)

	if !scan.Failed() {
		result := scan.FirstSuccessful
		for _, cert := range result.State.PeerCertificates {
			untilValid := time.Until(cert.NotBefore)
			if untilValid > 0 {
				return &BeforeValidationError{
					untilValid: untilValid,
					notBefore:  cert.NotBefore,
				}
			}
		}
	}
	return nil
}
