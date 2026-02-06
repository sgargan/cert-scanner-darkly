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
		Address: getAddress("0.0.0.0:33333"),
	}

	testutils.WithTestServerVersion(tls.VersionTLS12, 33333, func(testServer *testutils.TestTlsServer) error {
		// the majority will be handshake failures
		for _, result := range t.runScan(target) {
			if result.Failed() {
				t.ErrorContains(result.Results[0].Error, "protocol version not supported")
			} else {
				r := result.FirstSuccessful
				t.NotNil(r)
				t.NotNil(r.State)
				t.Equal(1, len(r.State.PeerCertificates))
				t.GreaterOrEqual(r.State.Version, uint16(tls.VersionTLS12))
				t.NotNil(r.Cipher)
			}
		}
		return nil
	})
}

func (t *CertScannerTests) TestConnectionError() {
	target := &Target{
		Address: CreateNetIPAddress(netip.MustParseAddrPort("127.0.0.1:33333")),
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
		Address: getAddress("127.0.0.1:33334"),
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
				Address:  getAddress(address),
			})
		}
	}
	return targets
}

func (t *CertScannerTests) runScan(target *Target) []*TargetScan {
	tlsRetrieval, err := CreateTLSStateRetrieval()
	t.NoError(err)
	results := make(chan *TargetScan)
	go func() {
		tlsRetrieval.Process(context.Background(), target, results)
		close(results)
	}()

	timeout := time.NewTimer(15 * time.Second)
	aggregatedResults := make([]*TargetScan, 0)
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

func getAddress(addr string) *NetIPAddress {
	return CreateNetIPAddress(netip.MustParseAddrPort(addr))
}

func (t *CertScannerTests) ValidateError(scan *TargetScan, errorType string) {
	r := scan.Results[0]
	t.NotNil(r.Error)
	t.True(r.Failed)
	t.Equal(errorType, r.Labels()["type"])
}

func TestCertScanner(t *testing.T) {
	suite.Run(t, &CertScannerTests{})
}
