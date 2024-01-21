package validations

import (
	"bufio"
	"crypto/x509"
	"fmt"
	"os"
	"testing"

	"github.com/sgargan/cert-scanner-darkly/testutils"
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
	result := CreateTestTargetScan().WithCertificates(cert).Build()
	t.NoError(t.sut.Validate(result))
}

func (t *TrustChainValidationTests) TestHasValidTrustChainFromPaths() {
	sut, err := CreateTrustChainValidationWithPaths(t.ca.WriteCerts())
	t.NoError(err)
	result := CreateTestTargetScan().WithCertificates(t.createTestCertFromCA(t.ca)).Build()
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
	result := CreateTestTargetScan().WithCertificates(cert).Build()
	t.ErrorContains(t.sut.Validate(result), "certificate signed by unknown authority")
}

func (t *TrustChainValidationTests) createTestCertFromCA(ca *TestCA) *x509.Certificate {
	cert, _, _, err := ca.CreateLeafCert("somehost")
	t.NoError(err)
	return cert
}

func (t *TrustChainValidationTests) TestLabels() {
	cert, _, _, err := t.ca.CreateLeafCert("somehost")
	t.NoError(err)
	scan := CreateTestTargetScan().WithTarget(testutils.TestTarget()).WithCertificates(cert).Build()
	scan.Results[0].Failed = true

	violation := TrustChainValidationError{
		err:    fmt.Errorf("something barfed"),
		result: scan.Results[0],
	}

	t.Equal(map[string]string{
		"address":     "172.1.2.34:8080",
		"common_name": "somehost",
		"failed":      "true",
		"foo":         "bar",
		"id":          fmt.Sprintf("%x", cert.SerialNumber),
		"source":      "SomePod-acdf-bdfe",
		"source_type": "kubernetes",
		"type":        "trust-chain",
	}, violation.Labels())
}

func TestTrustChainValidation(t *testing.T) {
	suite.Run(t, &TrustChainValidationTests{})
}
