package validations

import (
	"crypto/tls"
	"fmt"

	. "github.com/sgargan/cert-scanner-darkly/types"
)

const MaxInt = ^int(0) >> 1

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

func (e *TLSVersionValidationError) Labels() map[string]string {
	labels := e.result.Labels()
	labels["type"] = "tls_version"
	labels["detected_version"] = e.detectedVersion
	labels["min_version"] = e.minVersion
	return labels
}

func CreateTLSVersionValidation(minVersion string) (*TLSVersionValidation, error) {
	version, err := fromVersion(minVersion)
	if err != nil {
		return nil, err
	}
	return &TLSVersionValidation{minVersion: version}, nil
}

// Validate will check that the tls version is not less than the minimum configured version
func (v *TLSVersionValidation) Validate(scan *TargetScan) ScanError {
	result := scan.Results[0]
	if int(result.State.Version) < v.minVersion {
		return &TLSVersionValidationError{
			detectedVersion: toVersion(int(result.State.Version)),
			minVersion:      toVersion(v.minVersion),
		}
	}
	return nil
}

func toVersion(version int) string {
	switch version {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	}
	return "unknown"
}

// convert from a known string to a given tls version
func fromVersion(version string) (int, error) {
	switch version {
	case "1.0":
		return tls.VersionTLS10, nil
	case "1.1":
		return tls.VersionTLS11, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	}
	return MaxInt, fmt.Errorf("%s is not a valid tls version string use one of 1.0, 1.1, 1.2, 1.3", version)
}
