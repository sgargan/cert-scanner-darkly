package processors

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/stretchr/testify/suite"
)

type CertScannerTests struct {
	suite.Suite
}

func (t *CertScannerTests) TestScanValidTarget() {
	targets := GetTestTargets()
	result := t.runScan(targets[0])
	t.Equal(1, len(result.State.PeerCertificates))
	t.Equal(0, len(result.Errors))
	t.Equal(false, result.Failed)
}

func (t *CertScannerTests) TestConnectionError() {
	target := &Target{
		Address: netip.MustParseAddrPort("127.0.0.1:33333"),
	}
	result := t.runScan(target)
	t.ValidateError(result, "connection-error")
}

func (t *CertScannerTests) TestHandshakeError() {
	go func() {
		http.ListenAndServe("127.0.0.1:33334", nil)
	}()
	time.Sleep(50 * time.Millisecond)

	target := &Target{
		Address: netip.MustParseAddrPort("127.0.0.1:33334"),
	}
	scan := t.runScan(target)
	t.ValidateError(scan, "tls-handshake")
}

func GetTestTargets() []*Target {
	ips, _ := net.LookupIP("google.com")
	targets := make([]*Target, 0)
	for _, ip := range ips {
		if ip.To4() != nil {
			address := fmt.Sprintf("%s:%d", ip.String(), 443)
			targets = append(targets, &Target{
				Metadata: Metadata{},
				Address:  netip.MustParseAddrPort(address),
			})
		}
	}
	return targets
}

func (t *CertScannerTests) runScan(target *Target) *CertScanResult {
	tlsRetrieval, err := CreateTLSStateRetrieval()
	t.NoError(err)
	return tlsRetrieval.Process(context.Background(), target)
}

func (t *CertScannerTests) ValidateError(result *CertScanResult, errorType string) {
	t.Equal(1, len(result.Errors))
	t.Equal(true, result.Failed)
	t.Equal(errorType, result.Errors[0].Labels()["type"])
}

func TestCertScanner(t *testing.T) {
	suite.Run(t, &CertScannerTests{})
}
