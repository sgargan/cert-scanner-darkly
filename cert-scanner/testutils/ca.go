package testutils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

// CA represents one link in a trust chain
type CA struct {
	privateKey *rsa.PrivateKey
	cert       *x509.Certificate
	pem        []byte
}

// TestCA represents a full Certificate Authority trust chain
type TestCA struct {
	chain []*CA
}

func (t *TestCA) Root() *CA {
	if len(t.chain) > 0 {
		return t.chain[0]
	}
	return nil
}

func (t *TestCA) Bundle() *x509.CertPool {
	pool := x509.NewCertPool()
	for _, ca := range t.chain {
		pool.AddCert(ca.cert)
	}
	return pool
}

func (t *TestCA) WriteCerts() []string {
	paths := make([]string, 0)
	for x, ca := range t.chain {
		dir, _ := os.MkdirTemp("", "certs")
		path := fmt.Sprintf("%s/ca_%d", dir, x)
		os.WriteFile(path, ca.pem, 0600)
		paths = append(paths, path)
	}
	return paths
}

func (t *TestCA) CreateLeafCert(commonName string) (*x509.Certificate, []byte, *rsa.PrivateKey, error) {

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	return t.CreateLeafFromTemplate(&x509.Certificate{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Cert Scanner"},
			CommonName:   commonName,
		},
		SerialNumber:          serialNumber,
		NotBefore:             time.Now().Add(-10 * time.Second),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  false,
		BasicConstraintsValid: true,
		DNSNames:              []string{"127.0.0.1", "localhost"},
	})
}

func (t *TestCA) CreateLeafFromTemplate(template *x509.Certificate) (*x509.Certificate, []byte, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}

	intermediate := t.chain[len(t.chain)-1]
	cert, pem, err := createCert(template, intermediate, privateKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, pem, privateKey, err
}

// Creates a CA with a chain of the given length. The first cert will be a self signed root,
// and each subsequent intermediate issued by the cert before it in the list.
func CreateTestCA(length int) (*TestCA, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("error creating root ca private key: %v", err)
	}

	rootTemplate := createCATemplate("Test Root CA", length)
	rootCA, err := createCA(rootTemplate, &CA{
		cert:       rootTemplate,
		privateKey: privateKey,
	}, privateKey)

	if err != nil {
		return nil, err
	}

	chain := []*CA{rootCA}
	for x := 1; x < length; x++ {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("error creating ca private key: %v", err)
		}
		template := createCATemplate(fmt.Sprintf("Test Intermediate CA %d", x), length-x)
		intermediate, err := createCA(template, chain[x-1], privateKey)
		if err != nil {
			return nil, err
		}
		chain = append(chain, intermediate)
	}

	return &TestCA{
		chain: chain,
	}, nil
}

func createCert(template *x509.Certificate, parent *CA, privateKey *rsa.PrivateKey) (*x509.Certificate, []byte, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent.cert, &privateKey.PublicKey, parent.privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating cert from template: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing cert: %v", err)
	}

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	return cert, certPem, nil

}

func createCA(template *x509.Certificate, parent *CA, privateKey *rsa.PrivateKey) (*CA, error) {
	cert, certPem, err := createCert(template, parent, privateKey)
	if err != nil {
		return nil, err
	}

	return &CA{
		privateKey: privateKey,
		cert:       cert,
		pem:        certPem,
	}, nil
}

func createCATemplate(commonName string, pathLength int) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Cert Scanner"},
			CommonName:   commonName,
		},
		NotBefore:             time.Now().Add(-10 * time.Second),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            pathLength,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
}
