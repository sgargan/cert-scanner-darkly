package validations

import (
	"crypto/tls"
	"fmt"

	. "github.com/sgargan/cert-scanner-darkly/types"
	"golang.org/x/exp/slog"
)

type CipherSuiteValidation struct {
	allowedCiphers map[string]*tls.CipherSuite
}

type CipherSuiteValidationError struct {
	ScanError
	result *ScanResult
}

func (e *CipherSuiteValidationError) Error() string {
	return fmt.Sprintf("negotiated cipher that was not in the configured allowed list of ciphers")
}

func (e *CipherSuiteValidationError) Labels() map[string]string {
	labels := e.result.Labels()
	labels["type"] = "require_tls"
	return labels
}

func (e *CipherSuiteValidationError) Result() *ScanResult {
	return e.result
}

func CreateCipherSuiteValidation(allowedCiphersList []string) (*CipherSuiteValidation, error) {

	validCiphers := make(map[string]*tls.CipherSuite, 0)
	allowedCiphers := make(map[string]*tls.CipherSuite, 0)
	for _, cipher := range tls.CipherSuites() {
		validCiphers[cipher.Name] = cipher
	}

	for _, cipher := range allowedCiphersList {
		if allowedCipher, ok := validCiphers[cipher]; ok {
			allowedCiphers[cipher] = allowedCipher
		} else {
			return nil, fmt.Errorf("configured cipher %s not present in available tls.CipherSuite", cipher)
		}
	}

	if len(allowedCiphers) == 0 {
		return nil, fmt.Errorf("no allowed ciphers configured, check config for validations.cipher_suite.allowed_ciphers. Ensure that at least one of the configured ciphers is present in tls.CipherSuites")
	}

	return &CipherSuiteValidation{
		allowedCiphers: allowedCiphers,
	}, nil
}

// Validate will examine each scan result and raise a violation any ciphers were negotiated
// that are not on the configured allowed list.
func (v *CipherSuiteValidation) Validate(scan *TargetScan) ScanError {
	slog.Debug("validating target is using allowed ciphers", "target", scan.Target.Name)
	for _, result := range scan.Results {
		if _, allowed := v.allowedCiphers[result.Cipher.Name]; !allowed {
			return &CipherSuiteValidationError{result: result}
		}
	}
	return nil
}
