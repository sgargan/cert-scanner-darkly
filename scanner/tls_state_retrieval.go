package scanner

import (
	"context"
	"crypto/tls"
	"net"

	. "github.com/sgargan/cert-scanner-darkly/types"

	"github.com/sgargan/cert-scanner-darkly/utils"
)

type TLSStateRetrieval struct {
	parallel int
}

// CreateTLSStateRetrieval creates a scanner to retrieve TLS state information from Targets.
func CreateTLSStateRetrieval(parallel int) *TLSStateRetrieval {
	return &TLSStateRetrieval{
		parallel: parallel,
	}
}

// Scan each of the targets and extract the certificate/connection state for post processing. Targets will be processed in parallel
// number of concurrent retrievals can be controlled via the "batch.processors" configuration value.
func (c *TLSStateRetrieval) Scan(ctx context.Context, scan *Scan, targets []*Target) error {
	group := utils.BatchProcess[*Target](ctx, targets, c.parallel, func(ctx context.Context, target *Target) error {
		scan.AddResult(c.extractConnectionState(ctx, target))
		return nil
	})
	if err := group.Wait(); err != nil {
		return err
	}
	return nil
}

func (c *TLSStateRetrieval) extractConnectionState(ctx context.Context, target *Target) *CertScanResult {
	result := NewCertScanResult(target)
	dialer := &net.Dialer{}

	rawConn, err := dialer.DialContext(ctx, "tcp", target.Address.String())
	if err != nil {
		result.SetState(nil, CreateGenericError("connection-error", err))
		return result
	}

	if err == nil {
		// don't fail due errors like the servername or trust chain verification. Just pull
		// back the state and store it
		conn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: true})
		if err = conn.HandshakeContext(ctx); err != nil {
			result.SetState(nil, CreateGenericError("tls-handshake", err))
			rawConn.Close()
		} else {
			state := conn.ConnectionState()
			result.SetState(&state, nil)
		}
	}
	return result
}
