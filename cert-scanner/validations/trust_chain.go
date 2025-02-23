package validations

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	. "github.com/sgargan/cert-scanner-darkly/types"
	"golang.org/x/exp/slog"
)

type TrustChainValidation struct {
	rootCAs *x509.CertPool
}

type TrustChainValidationError struct {
	err    error
	cert   *x509.Certificate
	result *ScanResult
}

func (e *TrustChainValidationError) Error() string {
	return fmt.Sprintf("trust chain validation failed: %v", e.err)
}

func (e *TrustChainValidationError) Labels() map[string]string {
	labels := e.result.Labels()
	labels["type"] = "trust_chain"
	labels["subject_cn"] = e.cert.Subject.CommonName
	labels["issuer_cn"] = e.cert.Issuer.CommonName
	labels["authority_key_id"] = fmt.Sprintf("%x", e.cert.AuthorityKeyId)
	return labels
}

func (e *TrustChainValidationError) Result() *ScanResult {
	return e.result
}

// CreateTrustChainValidation creates a validation that will verify the trust chains
// of each cert in a scan result using root CA certs from the given paths.
func CreateTrustChainValidationWithPaths(caCertPaths []string) (*TrustChainValidation, error) {
	rootCAs := x509.NewCertPool()
	numCerts := 0
	slog.Info("loading ca certs", "num_certs", len(caCertPaths))
	for _, path := range caCertPaths {
		certBytes, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("error parsing cert: %v", err)
		}

		decodedPem, _ := pem.Decode(certBytes)
		if decodedPem == nil {
			return nil, fmt.Errorf("error decoding pem from: %v", path)
		}
		certs, err := x509.ParseCertificates(decodedPem.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing cert: %v", err)
		}
		slog.Info("loaded ca cert", "path", path, "certs", len(certs))
		for _, cert := range certs {
			numCerts += 1
			rootCAs.AddCert(cert)
		}
	}

	if numCerts == 0 {
		slog.Warn("no cert paths configured, using default system CA pool")
		systemCAs, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("error loading system cert bundle: %v", err)
		}
		return CreateTrustChainValidation(systemCAs), nil
	}
	slog.Info("trust_chain validation loaded all certs", "num_certs", numCerts)
	return CreateTrustChainValidation(rootCAs), nil
}

// CreateTrustChainValidation creates a validation that will verify the trust chains
// of each cert in a scan result using the given pool of root CA certs.
func CreateTrustChainValidation(rootCAs *x509.CertPool) *TrustChainValidation {
	return &TrustChainValidation{
		rootCAs: rootCAs,
	}
}

// Validate will verify the cert chain from the scan result using the configured pool
// of root CA certs ignoring any ServerNames in the certs.
func (v *TrustChainValidation) Validate(scan *TargetScan) ScanError {
	slog.Debug("validating trust of target", "target", scan.Target.Name)
	result := scan.FirstSuccessful
	if v.rootCAs == nil {
		return nil
	}

	state := result.State
	intermediates := x509.NewCertPool()
	for x, cert := range state.PeerCertificates {
		if x != 0 {
			intermediates.AddCert(cert)
		}
	}

	cert := result.State.PeerCertificates[0]
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:         v.rootCAs,
		CurrentTime:   time.Now(),
		DNSName:       "", // skip hostname verification
		Intermediates: intermediates,
	})

	if err != nil {
		return &TrustChainValidationError{
			result: result,
			cert:   cert,
			err:    fmt.Errorf("trust chain validation failed: %v", err),
		}
	}
	return nil
}
