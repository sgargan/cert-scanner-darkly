package processors

import (
	"context"
	"crypto/tls"
	"sort"
	"time"

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
// This is the main connection logic for the scanner and will use the configured cipher suites and
// versions to attempt to connect to the discovered targets. The results of each target scan are aggregated
// to report on after the scan is complete.
func CreateTLSStateRetrieval() (Processor, error) {
	return &TLSStateRetrieval{}, nil
}

func (c *TLSStateRetrieval) Process(ctx context.Context, target *Target, results chan<- *TargetScan) {
	// try each cipher from least to most secure until we fail to connect
	wait := &utils.ContextualWaitGroup{}
	targetScan := NewTargetScanResult(target)

	hasConnectionError := false
	for _, x := range orderedCipherSuites {
		cipher := x
		wait.Add(len(cipher.SupportedVersions))
		for _, v := range cipher.SupportedVersions {
			version := v
			go func() {
				defer wait.Done()
				result := NewScanResult()
				state, err := c.makeConnectionWithConfig(ctx, result, target, getConfig(target, cipher.ID, version))
				result.SetState(state, cipher, err)
				hasConnectionError = hasConnectionError || IsError(err, ConnectionError)
				targetScan.Add(result)
			}()
		}
	}
	wait.WaitWithContext(ctx)

	if hasConnectionError {
		slog.Error("error making connection to target", "address", target.Address.String())
	}
	results <- targetScan
}

func (c *TLSStateRetrieval) makeConnectionWithConfig(ctx context.Context, result *ScanResult, target *Target, config *tls.Config) (*tls.ConnectionState, ScanError) {
	slog.Debug("connecting to target", "target", target.Name, "address", target.Address.String(), "cipher", tls.CipherSuiteName(config.CipherSuites[0]), "version", tls.VersionName(config.MaxVersion))

	// Create a timeout context for both connect and handshake
	handshakeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	rawConn, err := target.Address.Connect(handshakeCtx)
	if err != nil {
		return nil, CreateGenericError(ConnectionError, err, result)
	}
	defer rawConn.Close()

	// attempt a handshake with the given config
	conn := tls.Client(rawConn, config)
	if err = conn.HandshakeContext(handshakeCtx); err != nil {
		return nil, &TLSConnectionError{
			config: *config,
			error:  err,
		}
	}
	state := conn.ConnectionState()
	return &state, nil
}

func getConfig(target *Target, cipher, version uint16) *tls.Config {
	config := &tls.Config{
		CipherSuites: []uint16{cipher},
		MaxVersion:   version,
		MinVersion:   version,
	}

	if target.Address.ValidateHostname() {
		config.ServerName = target.Address.String()
	} else {
		config.InsecureSkipVerify = true
	}
	return config
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

func (t *TLSConnectionError) Result() *ScanResult {
	return nil
}

func (t *TLSConnectionError) Labels() map[string]string {
	return map[string]string{
		"version": tls.VersionName(t.config.MaxVersion),
		"cipher":  tls.CipherSuiteName(t.config.CipherSuites[0]),
		"type":    HandshakeError,
	}
}
