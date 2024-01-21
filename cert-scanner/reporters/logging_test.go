package reporters

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/sgargan/cert-scanner-darkly/testutils"
	. "github.com/sgargan/cert-scanner-darkly/testutils"
	. "github.com/sgargan/cert-scanner-darkly/types"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/suite"
)

var target = testutils.TestTarget()

type LoggingTests struct {
	suite.Suite
	logFile string
	scan    *TargetScan
	sut     *LoggingReporter
}

func (t *LoggingTests) SetupTest() {
	testlog, err := os.CreateTemp("", "testlog")
	t.logFile = testlog.Name()

	viper.Set("reporters.logging.file", t.logFile)
	t.sut, err = CreateLoggingReporterWithPath(t.logFile)
	t.NoError(err)

	ca, _ := CreateTestCA(1)
	cert, _, _, _ := ca.CreateLeafCert("somehost")
	cert.SerialNumber = (&big.Int{}).SetBytes([]byte{1, 2, 3, 4})

	testScan := CreateTestTargetScan().WithCertificates(cert).WithTarget(testutils.TestTarget())
	result, violation := createTestViolation()
	t.scan = testScan.WithScanResult(result).WithDuration(time.Duration(123)).WithViolation(violation).Build()

}

func (t *LoggingTests) TestReportsSuccessfulResultToLog() {
	t.sut.Report(context.Background(), t.scan)
	t.sut.Close()

	lines := toJsonList(t.logFile)

	delete(lines[0], "time")
	t.Equal(map[string]interface{}{
		"address":          "172.1.2.34:8080",
		"common_name":      "somehost",
		"failed":           "true",
		"foo":              "bar",
		"id":               "1020304",
		"level":            "INFO",
		"msg":              "violation",
		"not_after":        "1673740800000",
		"source":           "SomePod-acdf-bdfe",
		"source_type":      "kubernetes",
		"type":             "expiry",
		"warning_duration": "168h0m0s",
	}, lines[0])
}

func (t *LoggingTests) TestReportsFailingResultToLog() {
	t.sut.Report(context.Background(), t.scan)
	t.sut.Report(context.Background(), t.scan)
	t.sut.Close()

	lines := toJsonList(t.logFile)
	t.Greater(len(lines), 0)
	delete(lines[1], "time")
	t.Equal(map[string]interface{}{
		"address":          "172.1.2.34:8080",
		"common_name":      "somehost",
		"failed":           "true",
		"foo":              "bar",
		"id":               "1020304",
		"level":            "INFO",
		"msg":              "violation",
		"not_after":        "1673740800000",
		"source":           "SomePod-acdf-bdfe",
		"source_type":      "kubernetes",
		"type":             "expiry",
		"warning_duration": "168h0m0s",
	}, lines[1])
}

func toJsonList(filename string) []map[string]interface{} {
	asList := make([]map[string]interface{}, 0)
	f, _ := os.Open(filename)

	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadBytes('\n')
		if err == io.EOF {
			break
		}

		asMap := make(map[string]interface{})
		err = json.Unmarshal(line, &asMap)
		if err != nil {
			panic(fmt.Sprintf("error converting log line to json %s - %v", string(line), err))
		}
		asList = append(asList, asMap)
	}
	return asList
}

func TestLoggingTests(t *testing.T) {
	suite.Run(t, &LoggingTests{})
}
