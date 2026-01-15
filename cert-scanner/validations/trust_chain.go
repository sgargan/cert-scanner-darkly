package validations

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/sgargan/cert-scanner-darkly/config"
	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/spf13/viper"
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
	subject := "n/a"
	issuer := "n/a"
	authorityKeyId := []byte{}
	if e.cert != nil {
		subject = e.cert.Subject.CommonName
		issuer = e.cert.Issuer.CommonName
		authorityKeyId = e.cert.AuthorityKeyId
	}
	labels := e.result.Labels()
	labels["type"] = "trust_chain"
	labels["subject_cn"] = subject
	labels["issuer_cn"] = issuer
	labels["authority_key_id"] = fmt.Sprintf("%x", authorityKeyId)
	return labels
}

func (e *TrustChainValidationError) Result() *ScanResult {
	return e.result
}

// CreateTrustChainValidation creates a validation that will verify the trust chains
// of each cert in a scan result using root CA certs from the given paths.
func CreateTrustChainValidationWithPaths(caCertPaths []string) (*TrustChainValidation, error) {
	rootCAs := x509.NewCertPool()
	if viper.GetBool(config.ValidationsTrustChainSystemRoots) {
		var err error
		if rootCAs, err = x509.SystemCertPool(); err != nil {
			return nil, fmt.Errorf("error loading system root certs - %v", err)
		}
	}

	slog.Info("loading ca certs", "num_paths", len(caCertPaths))
	numCerts, err := loadCaCertsFromPaths(rootCAs, caCertPaths)
	if err != nil {
		return nil, err
	}

	slog.Info("trust_chain validation loaded all certs", "num_certs", numCerts)
	return CreateTrustChainValidation(rootCAs), err
}

// CreateTrustChainValidation creates a validation that will verify the trust chains
// of each cert in a scan result using the given pool of root CA certs.
func CreateTrustChainValidation(rootCAs *x509.CertPool) *TrustChainValidation {
	return &TrustChainValidation{
		rootCAs: rootCAs,
	}
}

func loadCaCertsFromPaths(rootCAs *x509.CertPool, caCertPaths []string) (int, error) {
	numCerts := 0
	for _, path := range caCertPaths {
		certBytes, err := os.ReadFile(path)
		if err != nil {
			return 0, fmt.Errorf("error reading cert file %s: %v", path, err)
		}

		rest := certBytes
		var block *pem.Block
		for {
			block, rest = pem.Decode(rest)

			if block == nil {
				break
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				// we don't necessarily want to error out here if one of the certs is invalid
				// this might not be something that we have control over if the bundle is provided
				// count the number of certs and report this up
				slog.Error("Failed to parse certificate", "error", err)
				continue
			}
			rootCAs.AddCert(cert)
			numCerts += 1
			slog.Debug("added ca cert", "subject", cert.Subject.CommonName, "issuer", cert.Issuer.CommonName, "authority_key_id", fmt.Sprintf("%x", cert.AuthorityKeyId))
		}
	}
	return numCerts, nil
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

	// if the target has a url then verify the hostname
	// otherwise skip the name validation.
	expectedName := ""
	switch scan.Target.Address.(type) {
	case *UrlAddress:
		expectedName = scan.Target.Address.String()
	}

	cert := result.State.PeerCertificates[0]
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:         v.rootCAs,
		CurrentTime:   time.Now(),
		DNSName:       expectedName,
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
