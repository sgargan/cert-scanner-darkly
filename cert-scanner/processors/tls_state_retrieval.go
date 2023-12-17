package processors

import (
	"context"
	"crypto/tls"
	"net"
	"sort"

	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/sgargan/cert-scanner-darkly/utils"
	"golang.org/x/exp/slices"
)

var orderedCipherSuites []*tls.CipherSuite

type TLSStateRetrieval struct{}

func init() {
	orderedCipherSuites = sortCiphers()
}

// CreateTLSStateRetrieval creates a scanner to retrieve TLS state information from Targets.
func CreateTLSStateRetrieval() (Processor, error) {
	return &TLSStateRetrieval{}, nil
}

func (c *TLSStateRetrieval) Process(ctx context.Context, target *Target, results chan<- *CertScanResult) {
	// try each cipher from least to most secure until we fail to connect
	wait := &utils.ContextualWaitGroup{}
	for _, cipher := range orderedCipherSuites {
		wait.Add(len(cipher.SupportedVersions))
		for _, version := range cipher.SupportedVersions {
			go func() {
				defer wait.Done()
				state, err := c.makeConnectionWithConfig(ctx, target, getConfig(cipher.ID, version))
				result := NewCertScanResult(target)
				result.SetState(state, cipher, err)
				results <- result
			}()
		}
	}
	wait.WaitWithContext(ctx)
}

func (c *TLSStateRetrieval) makeConnectionWithConfig(ctx context.Context, target *Target, config *tls.Config) (*tls.ConnectionState, ScanError) {
	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(ctx, "tcp", target.Address.String())
	if err != nil {
		return nil, CreateGenericError(ConnectionError, err)
	} else {
		defer rawConn.Close()

		// attempt a handshake with the given config
		conn := tls.Client(rawConn, config)
		if err = conn.HandshakeContext(ctx); err != nil {
			return nil, CreateGenericError(HandshakeError, err)
		}
		state := conn.ConnectionState()
		return &state, nil
	}
}

func getConfig(cipher, version uint16) *tls.Config {
	// skip validation here so we as not to fail due errors like the servername or trust chain verification.
	// these will get validated later
	return &tls.Config{
		InsecureSkipVerify: true,
		CipherSuites:       []uint16{cipher},
		MaxVersion:         version,
		MinVersion:         version,
	}
}

func sortCiphers() []*tls.CipherSuite {
	ordered := slices.Clone[[]*tls.CipherSuite, *tls.CipherSuite](tls.CipherSuites())
	ordered = append(ordered, tls.InsecureCipherSuites()...)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].SupportedVersions[0] < ordered[j].SupportedVersions[0]
	})
	return ordered
}
