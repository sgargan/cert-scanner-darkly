package scanner

import (
	"context"
	"reflect"
	"runtime"
	"sync"

	. "github.com/sgargan/cert-scanner-darkly/types"
	"github.com/sgargan/cert-scanner-darkly/utils"
	"github.com/spf13/viper"
	"golang.org/x/exp/slog"
)

// Scan aggregates the results of cert extraction from each discovered target and takes care of subsequently
// validating and reporting on each.
type Scan struct {
	sync.Mutex
	parallel    int
	Results     []*CertScanResult
	validations Validations
	reporters   Reporters
}

func CreateScan(validations Validations, reporters Reporters) *Scan {
	return &Scan{
		parallel:    getBatchSize(),
		Results:     make([]*CertScanResult, 0),
		validations: validations,
		reporters:   reporters,
	}
}

func (s *Scan) AddResult(result *CertScanResult) {
	s.Lock()
	defer s.Unlock()
	s.Results = append(s.Results, result)
}

// Retrieve will connect to each of the given [Targets] and initiate a tls connection. The resulting tls state gets stored
// for validation. Retrieval is done in parallel and can be controlled via the 'batch.processors' config entry, defaulting to the
// number of available processors
func (s *Scan) Retrieve(ctx context.Context, targets []*Target) error {
	tsr := CreateTLSStateRetrieval(s.parallel)
	return tsr.Scan(ctx, s, targets)
}

// Validate will process each of the extracted tls states and apply a series of validations to verify the contained certs are ok. Validations
// are is done in parallel and can be controlled via the 'batch.processors' config entry, defaulting to the number of available processors
func (s *Scan) Validate(ctx context.Context) error {
	group := utils.BatchProcess[*CertScanResult](ctx, s.Results, s.parallel, func(ctx context.Context, result *CertScanResult) error {
		slog.Debug("validating result", "target", result.Target.Name)
		if !result.Failed {
			for _, validation := range s.validations {
				result.Fail(validation.Validate(result))
			}
		}
		return nil
	})
	return group.Wait()
}

// Report will process all validated results allowing us to act on detected violations. Reporters are configurable via the 'reporters' stanza in the config.
// Reporters will ber run in parallel with each reporter processing the full results serially.
func (s *Scan) Report(ctx context.Context) error {
	group := utils.BatchProcess[Reporter](ctx, s.reporters, len(s.reporters), func(ctx context.Context, reporter Reporter) error {
		slog.Debug("reporting on result", "reporter", reflect.TypeOf(reporter).Name())
		for _, result := range s.Results {
			reporter.Report(ctx, result)
		}
		return nil
	})
	return group.Wait()
}

func getBatchSize() int {
	if batchSize := viper.GetInt("batch.processors"); batchSize == 0 {
		return runtime.NumCPU()
	} else {
		return batchSize
	}
}
