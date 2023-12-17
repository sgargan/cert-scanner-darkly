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
	c           int
	Results     []*CertScanResult
	processors  Processors
	discoveries Discoveries
	validations Validations
	reporters   Reporters
}

func CreateScan(discoveries Discoveries, processors Processors, validations Validations, reporters Reporters) *Scan {
	return &Scan{
		parallel:    getBatchSize(),
		Results:     make([]*CertScanResult, 0),
		discoveries: discoveries,
		processors:  processors,
		validations: validations,
		reporters:   reporters,
	}
}

func (s *Scan) Scan(ctx context.Context) error {
	targets, err := s.discover(ctx)
	if err != nil {
		return err
	}

	s.process(ctx, targets)
	s.validate(ctx)
	s.report(ctx)
	return nil
}

func (s *Scan) AddResult(result *CertScanResult) {
	s.Lock()
	defer s.Unlock()
	s.c++
	s.Results = append(s.Results, result)
}

// process each of the targets and extract the certificate/connection state for post processing. Targets will be processed in parallel
// number of concurrent retrievals can be controlled via the "batch.processors" configuration value.
func (s *Scan) process(ctx context.Context, targets []*Target) error {
	results := make(chan *CertScanResult)
	wait := sync.WaitGroup{}
	wait.Add(1)
	go func() {
		for {
			select {
			case result, ok := <-results:
				if !ok {
					wait.Done()
					return
				}
				s.AddResult(result)
			case <-ctx.Done():
				return
			}
		}
	}()

	group := utils.BatchProcess[*Target](ctx, targets, s.parallel, func(ctx context.Context, target *Target) error {
		for _, processor := range s.processors {
			processor.Process(ctx, target, results)
		}
		return nil
	})
	err := group.Wait()
	close(results)
	wait.Wait()
	slog.Info("Processing complete", "results", len(s.Results))
	return err
}

// discover runs each of the [Discovery] mechanims in parallel to determin target services for further processing
// are is done in parallel and can be controlled via the 'batch.processors' config entry, defaulting to the number of available processors
func (s *Scan) discover(ctx context.Context) ([]*Target, error) {
	// var c1, c2 atomic.Int32
	targets := make(chan *Target)
	aggregated := make([]*Target, 0)
	wait := sync.WaitGroup{}
	wait.Add(1)
	go func() {
		defer wait.Done()
		for target := range targets {
			aggregated = append(aggregated, target)
		}
	}()

	group := utils.BatchProcess[Discovery](ctx, s.discoveries, s.parallel, func(ctx context.Context, discovery Discovery) error {
		slog.Info("Discovering targets", "discovery", reflect.TypeOf(discovery).Name())
		return discovery.Discover(ctx, targets)
	})
	err := group.Wait()
	close(targets)
	wait.Wait()
	return aggregated, err
}

// validate will process each of the extracted tls states and apply a series of validations to verify the contained certs are ok. Validations
// are is done in parallel and can be controlled via the 'batch.processors' config entry, defaulting to the number of available processors
func (s *Scan) validate(ctx context.Context) error {
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

// report will process all validated results allowing us to act on detected violations. Reporters are configurable via the 'reporters' stanza in the config.
// Reporters will ber run in parallel with each reporter processing the full results serially.
func (s *Scan) report(ctx context.Context) error {
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
