package canary

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/sgargan/cert-scanner-darkly/testutils"
	"golang.org/x/exp/slog"
)

func RunCanary(port int) {
	ca, err := testutils.CreateTestCA(1)
	failOnError("error creating ca for canary", err)
	serial, err := testutils.CreateSerialNumber()
	failOnError("error creating serial for certificate", err)

	// setup the cert to expire iminently
	template := testutils.CreateLeafTemplate("some-server", serial)
	template.NotAfter = time.Now()

	_, certPem, key, err := ca.CreateLeafFromTemplate(template)
	failOnError("error creating certificate for server", err)

	// create server with 1.1 config
	config := testutils.CreateTestTLSConfig(tls.VersionTLS11, certPem, key)
	testutils.NewTestTlsServerWithHandler(config, port, handler)

	fmt.Printf("Running canary on :%d\n", port)
	wg := sync.WaitGroup{}
	wg.Add(1)
	wg.Wait()
}

func handler(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

func failOnError(message string, err error) {
	if err != nil {
		slog.Error(message, "err", err.Error())
		os.Exit(1)
	}
}
