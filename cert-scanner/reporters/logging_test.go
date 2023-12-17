package reporters

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	. "github.com/sgargan/cert-scanner-darkly/testutils"
	. "github.com/sgargan/cert-scanner-darkly/types"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/suite"
)

type LoggingTests struct {
	suite.Suite
	logFile string
	sut     *LoggingReporter
}

func (t *LoggingTests) SetupTest() {
	testlog, err := os.CreateTemp("", "testlog")
	t.logFile = testlog.Name()

	viper.Set("reporters.logging.file", t.logFile)
	t.sut, err = CreateLoggingReporterWithPath(t.logFile)
	t.NoError(err)
}

func (t *LoggingTests) TestReportsSuccessfulResultToLog() {
	result := CreateTestCertScanResult().WithTarget(target).Build()
	result.Duration = time.Duration(123)
	t.sut.Report(context.Background(), result)
	t.sut.Close()

	lines := toJsonList(t.logFile)

	delete(lines[0], "time")
	t.Equal(map[string]interface{}{"address": "172.1.2.34:8080", "level": "INFO", "msg": "duration", "source": "SomePod-acdf-bdfe", "source_type": "kubernetes", "failed": "false", "foo": "bar", "duration": "123000000"}, lines[0])
}

func (t *LoggingTests) TestReportsFailingResultToLog() {
	err := CreateGenericError("some-error", errors.New("something-barfed"))
	result := CreateTestCertScanResult().WithTarget(target).WithError(err).Build()
	result.Duration = time.Duration(123)
	t.sut.Report(context.Background(), result)
	t.sut.Close()

	lines := toJsonList(t.logFile)

	delete(lines[1], "time")
	t.Equal(map[string]interface{}{"address": "172.1.2.34:8080", "level": "INFO", "msg": "violation", "source": "SomePod-acdf-bdfe", "source_type": "kubernetes", "failed": "true", "foo": "bar", "type": "some-error"}, lines[1])
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
