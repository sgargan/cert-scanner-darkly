package processors

import (
	"context"
	"crypto/tls"
	"net"

	. "github.com/sgargan/cert-scanner-darkly/types"
)

type TLSStateRetrieval struct{}

// CreateTLSStateRetrieval creates a scanner to retrieve TLS state information from Targets.
func CreateTLSStateRetrieval() (Processor, error) {
	return &TLSStateRetrieval{}, nil
}

func (c *TLSStateRetrieval) Process(ctx context.Context, target *Target) *CertScanResult {
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
