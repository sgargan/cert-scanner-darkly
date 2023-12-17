package processors

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/sgargan/cert-scanner-darkly/testutils"
	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/stretchr/testify/suite"
)

type CertScannerTests struct {
	suite.Suite
}

func (t *CertScannerTests) TestScanValidTarget() {
	target := &Target{
		Address: netip.MustParseAddrPort("0.0.0.0:33333"),
	}

	testutils.WithTestServerVersion(tls.VersionTLS12, 33333, func(testServer *testutils.TestTlsServer) error {
		results := t.runScan(target)
		if results != nil {
			// the majority will be handshake failures
			for _, result := range results {
				if result.Failed {
					t.ErrorContains(result.Errors[0], "handshake failure")
				} else {
					t.Equal(1, len(result.State.PeerCertificates))
					t.GreaterOrEqual(result.State.Version, uint16(tls.VersionTLS12))
					t.NotNil(result.Cipher)
				}
			}
		}

		return nil
	})
}

func (t *CertScannerTests) TestConnectionError() {
	target := &Target{
		Address: netip.MustParseAddrPort("127.0.0.1:33333"),
	}
	results := t.runScan(target)
	t.ValidateError(results[0], ConnectionError)
}

func (t *CertScannerTests) TestHandshakeError() {
	go func() {
		http.ListenAndServe("127.0.0.1:33334", nil)
	}()
	time.Sleep(50 * time.Millisecond)

	target := &Target{
		Address: netip.MustParseAddrPort("127.0.0.1:33334"),
	}
	results := t.runScan(target)
	t.ValidateError(results[0], "tls-handshake")
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

func (t *CertScannerTests) runScan(target *Target) []*CertScanResult {
	tlsRetrieval, err := CreateTLSStateRetrieval()
	t.NoError(err)
	results := make(chan *CertScanResult)
	go func() {
		tlsRetrieval.Process(context.Background(), target, results)
		close(results)
	}()

	timeout := time.NewTimer(15 * time.Second)
	aggregatedResults := make([]*CertScanResult, 0)
	for {
		select {
		case <-timeout.C:
			t.FailNow("timeout waiting for result")
			return nil
		case result, ok := <-results:
			if !ok {
				return aggregatedResults
			}
			aggregatedResults = append(aggregatedResults, result)
		}
	}
}

func (t *CertScannerTests) ValidateError(result *CertScanResult, errorType string) {
	t.Equal(1, len(result.Errors))
	t.Equal(true, result.Failed)
	t.Equal(errorType, result.Errors[0].Labels()["type"])
}

func TestCertScanner(t *testing.T) {
	suite.Run(t, &CertScannerTests{})
}
