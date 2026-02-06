package validations

import (
	. "github.com/sgargan/cert-scanner-darkly/types"
	"golang.org/x/exp/slog"
)

type RequireTLSValidation struct {
}

type RequireTLSValidationError struct {
	ScanError
	result *ScanResult
}

func CreateRequireTLSValidation() *RequireTLSValidation {
	return &RequireTLSValidation{}
}

func (e *RequireTLSValidationError) Error() string {
	return "Target is not configured with TLS"
}

func (e *RequireTLSValidationError) Labels() map[string]string {
	if e.result == nil {
		return map[string]string{"type": "require_tls"}
	}
	labels := e.result.Labels()
	labels["type"] = "require_tls"
	return labels
}

// Validate will examine each scan result and raise a violation if no TLS was discovered for the target
func (v *RequireTLSValidation) Validate(scan *TargetScan) ScanError {
	slog.Debug("validating target is configured with TLS", "target", scan.Target.Name)

	var lastFailed *ScanResult
	for _, result := range scan.Results {
		if !result.Failed {
			// any successful result is a pass
			return nil
		}
		lastFailed = result
	}

	return &RequireTLSValidationError{
		result: lastFailed,
	}
}
