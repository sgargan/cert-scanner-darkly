package testutils

import (
	"crypto"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"
)

type TestTlsServer struct {
	config *tls.Config
	server *http.Server
	done   chan bool
}

func DefaultHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("OK"))
	w.WriteHeader(200)
}

func NewTestTlsServer(config *tls.Config, port int) *TestTlsServer {
	return NewTestTlsServerWithHandler(config, port, DefaultHandler)
}

func NewTestTlsServerWithHandler(config *tls.Config, port int, handler http.HandlerFunc) *TestTlsServer {
	server := &TestTlsServer{
		config: config,
		server: &http.Server{Addr: fmt.Sprintf("0.0.0.0:%d", port), Handler: handler, TLSConfig: config},
		done:   make(chan bool),
	}

	go func() {
		switch {
		case <-server.done:
			server.server.Close()
		}
	}()

	go func() {
		fmt.Println(server.server.ListenAndServeTLS("", ""))
	}()

	time.Sleep(100 * time.Millisecond)
	return server
}

func WithTestServerFromConfig(config *tls.Config, port int, handler func(testServer *TestTlsServer) error) error {
	server := NewTestTlsServer(config, port)
	defer server.Stop()
	return handler(server)
}

func WithTestServerVersion(tlsVersion uint16, port int, handler func(testServer *TestTlsServer) error) error {
	ca, err := CreateTestCA(0)
	if err != nil {
		return err
	}

	_, certPem, key, err := ca.CreateLeafCert("some-server")
	if err != nil {
		return err
	}

	return WithTestServerFromConfig(CreateTestTLSConfig(tlsVersion, certPem, key), port, handler)
}

func CreateTestTLSConfig(tlsVersion uint16, certPem []byte, key crypto.PrivateKey) *tls.Config {
	raw, _ := pem.Decode(certPem)

	return &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{raw.Bytes},
				PrivateKey:  key,
			},
		},
		MinVersion: tlsVersion,
		// PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
}

func (t *TestTlsServer) Stop() {
	t.done <- true
}
