package validations

import (
	"fmt"

	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/sgargan/cert-scanner-darkly/utils"
	"golang.org/x/exp/slog"
)

type TLSVersionValidation struct {
	minVersion int
}

type TLSVersionValidationError struct {
	detectedVersion string
	minVersion      string
	result          *ScanResult
}

func (e *TLSVersionValidationError) Error() string {
	return fmt.Sprintf("connection supports an invalid tls version %s, min version is %s", e.detectedVersion, e.minVersion)
}

func (e *TLSVersionValidationError) Result() *ScanResult {
	return e.result
}

func (e *TLSVersionValidationError) Labels() map[string]string {
	labels := e.result.Labels()
	labels["type"] = "tls_version"
	labels["detected_version"] = e.detectedVersion
	labels["min_version"] = e.minVersion
	return labels
}

func CreateTLSVersionValidation(minVersion string) (*TLSVersionValidation, error) {
	version, err := utils.FromVersion(minVersion)
	if err != nil {
		return nil, err
	}
	return &TLSVersionValidation{minVersion: version}, nil
}

// Validate will check that the tls version is not less than the minimum configured version
func (v *TLSVersionValidation) Validate(scan *TargetScan) ScanError {
	slog.Debug("validating tls version of target", "target", scan.Target.Name)
	result := scan.FirstSuccessful
	if int(result.State.Version) < v.minVersion {
		return &TLSVersionValidationError{
			detectedVersion: utils.ToVersion(int(result.State.Version)),
			minVersion:      utils.ToVersion(v.minVersion),
			result:          result,
		}
	}
	return nil
}
