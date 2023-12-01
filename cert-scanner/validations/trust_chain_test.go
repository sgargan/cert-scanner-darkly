package validations

import (
	"bufio"
	"crypto/x509"
	"fmt"
	"os"
	"testing"

	. "github.com/sgargan/cert-scanner-darkly/testutils"
	"github.com/stretchr/testify/suite"
)

type TrustChainValidationTests struct {
	suite.Suite
	ca  *TestCA
	sut *TrustChainValidation
}

func (t *TrustChainValidationTests) SetupTest() {
	ca, err := CreateTestCA(3)
	t.NoError(err)
	t.ca = ca
	t.sut = CreateTrustChainValidation(t.ca.Bundle())
}

func (t *TrustChainValidationTests) TestHasValidTrustChain() {
	cert := t.createTestCertFromCA(t.ca)
	result := CreateTestCertScanResult().WithCertificates(cert).Build()
	t.NoError(t.sut.Validate(result))
}

func (t *TrustChainValidationTests) TestHasValidTrustChainFromPaths() {
	sut, err := CreateTrustChainValidationWithPaths(t.ca.WriteCerts())
	t.NoError(err)
	result := CreateTestCertScanResult().WithCertificates(t.createTestCertFromCA(t.ca)).Build()
	t.NoError(sut.Validate(result))
}

func (t *TrustChainValidationTests) TestErrorLoadingCertsFromPaths() {
	_, err := CreateTrustChainValidationWithPaths([]string{"/does/not/exists"})
	t.Error(err)
}

func (t *TrustChainValidationTests) TestErrorBogusCertsFromPaths() {
	corrupted := `\n-----BEGIN CERTIFICATE\n Corrupted \n-----END CERTIFICATE\n`
	bogusCaFile, _ := os.CreateTemp("", "bogusca")
	len, err := bufio.NewWriter(bogusCaFile).WriteString(corrupted)
	t.Greater(len, 0)
	t.NoError(err)

	_, err = CreateTrustChainValidationWithPaths([]string{bogusCaFile.Name()})
	t.Error(err)
}

func (t *TrustChainValidationTests) TestHasInvalidTrustChain() {
	unknownCa, _ := CreateTestCA(3)
	cert := t.createTestCertFromCA(unknownCa)
	result := CreateTestCertScanResult().WithCertificates(cert).Build()
	t.ErrorContains(t.sut.Validate(result), "certificate signed by unknown authority")
}

func (t *TrustChainValidationTests) createTestCertFromCA(ca *TestCA) *x509.Certificate {
	cert, _, _, err := ca.CreateLeafCert("somehost")
	t.NoError(err)
	return cert
}

func (t *TrustChainValidationTests) TestLabels() {
	err := TrustChainValidationError{
		err: fmt.Errorf("something barfed"),
	}
	t.Equal(map[string]string{
		"type": "trust-chain",
	}, err.Labels())
}

func TestTrustChainValidation(t *testing.T) {
	suite.Run(t, &TrustChainValidationTests{})
}
