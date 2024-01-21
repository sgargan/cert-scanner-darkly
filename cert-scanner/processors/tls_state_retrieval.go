package processors

import (
	"context"
	"crypto/tls"
	"net"
	"sort"

	"golang.org/x/exp/slog"

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

func (c *TLSStateRetrieval) Process(ctx context.Context, target *Target, results chan<- *TargetScan) {
	// try each cipher from least to most secure until we fail to connect
	wait := &utils.ContextualWaitGroup{}
	targetScan := NewTargetScanResult(target)

	for _, x := range orderedCipherSuites {
		cipher := x
		wait.Add(len(cipher.SupportedVersions))
		for _, v := range cipher.SupportedVersions {
			version := v
			go func() {
				defer wait.Done()
				result := NewScanResult()
				state, err := c.makeConnectionWithConfig(ctx, target, getConfig(cipher.ID, version))
				result.SetState(state, cipher, err)
				targetScan.Add(result)
			}()
		}
	}
	wait.WaitWithContext(ctx)
	results <- targetScan
}

func (c *TLSStateRetrieval) makeConnectionWithConfig(ctx context.Context, target *Target, config *tls.Config) (*tls.ConnectionState, ScanError) {
	slog.Debug(" connecting to target", "target", target.Name, "address", target.Address, "cipher", tls.CipherSuiteName(config.CipherSuites[0]), "version", config.MaxVersion)
	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(ctx, "tcp", target.Address.String())
	if err != nil {
		return nil, CreateGenericError(ConnectionError, err)
	} else {
		defer rawConn.Close()

		// attempt a handshake with the given config
		conn := tls.Client(rawConn, config)
		if err = conn.HandshakeContext(ctx); err != nil {

			return nil, &TLSConnectionError{
				config: *config,
				error:  err,
			}
		}
		state := conn.ConnectionState()
		return &state, nil
	}
}

func getConfig(cipher, version uint16) *tls.Config {
	// skip validation here so we as not to fail due errors like the servername or trust chain verification.
	// these will get validated later
	slog.Debug("cipher name ", "cipher", tls.CipherSuiteName(cipher), "version", tls.VersionName(version))
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

type TLSConnectionError struct {
	config tls.Config
	error
}

func (t *TLSConnectionError) Labels() map[string]string {
	return map[string]string{
		"version": tls.VersionName(t.config.MaxVersion),
		"cipher":  tls.CipherSuiteName(t.config.CipherSuites[0]),
		"type":    HandshakeError,
	}
}
