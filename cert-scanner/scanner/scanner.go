package scanner

import (
	"context"
	"path"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"

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
	TargetScans []*TargetScan
	processors  Processors
	discoveries Discoveries
	validations Validations
	reporters   Reporters
}

func CreateScan(discoveries Discoveries, processors Processors, validations Validations, reporters Reporters) *Scan {
	return &Scan{
		parallel:    getBatchSize(),
		TargetScans: make([]*TargetScan, 0),
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

func (s *Scan) AddResult(result *TargetScan) {
	s.Lock()
	defer s.Unlock()
	s.TargetScans = append(s.TargetScans, result)
}

func (s *Scan) Results() []*TargetScan {
	return s.TargetScans
}

// process each of the targets and extract the certificate/connection state for post processing. Targets will be processed in parallel
// number of concurrent retrievals can be controlled via the "batch.processors" configuration value.
func (s *Scan) process(ctx context.Context, targets []*Target) error {
	total := int64(len(targets))
	slog.Info("starting processing discovered targets", "targets", total)
	results := make(chan *TargetScan)
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
				slog.Debug("aggregating scan result", "target", result.Target.Address.String(), "remaining", atomic.AddInt64(&total, -1))
				s.AddResult(result)
			case <-ctx.Done():
				slog.Warn("Context cancelled before all processing result gathered")
				return
			}
		}
	}()

	group := utils.BatchProcess[*Target](ctx, targets, s.parallel, func(ctx context.Context, target *Target) error {
		for _, processor := range s.processors {
			processor.Process(ctx, target, results)
		}
		slog.Debug("finished processing target", "target", target.Name, "address", target.Address.String())
		return nil
	})

	err := group.Wait()
	close(results)
	wait.Wait()
	slog.Info("finished processing discovered targets", "results", len(s.TargetScans))
	return err
}

// discover runs each of the [Discovery] mechanims in parallel to determine target services for further processing. Discoveries
// are is done in parallel and can be controlled via the 'batch.processors' config entry, defaulting to the number of available processors
func (s *Scan) discover(ctx context.Context) ([]*Target, error) {
	slog.Info("starting discoveries", "target_scans", len(s.TargetScans))

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
		slog.Info("Discovering targets", "discovery", getPkgName(discovery))
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
	slog.Info("starting validation", "target_scans", len(s.TargetScans))

	group := utils.BatchProcess[*TargetScan](ctx, s.TargetScans, s.parallel, func(ctx context.Context, targetScan *TargetScan) error {
		slog.Debug("validating target scan", "target", targetScan.Target.Name)
		// if targetScan.ShouldValidate() {
		for _, validation := range s.validations {
			targetScan.AddViolation(validation.Validate(targetScan))
		}
		// }
		return nil
	})
	err := group.Wait()
	slog.Info("finishied validations", "target_scans", len(s.TargetScans))
	return err
}

// report will process all validated TargetScans allowing us to act on detected violations. Reporters are configurable via the 'reporters' stanza in the config.
// Reporters will ber run in parallel with each reporter processing the full results serially.
func (s *Scan) report(ctx context.Context) error {
	slog.Info("starting reporting", "target_scans", len(s.TargetScans))

	group := utils.BatchProcess[Reporter](ctx, s.reporters, len(s.reporters), func(ctx context.Context, reporter Reporter) error {
		slog.Debug("reporting on target scans", "reporter", getTypeName(reporter))
		for _, result := range s.TargetScans {
			reporter.Report(ctx, result)
		}
		return nil
	})
	return group.Wait()
}

func getBatchSize() int {
	if batchSize := viper.GetInt("batch.processors"); batchSize == 0 {
		return runtime.NumCPU() + 1
	} else {
		return batchSize
	}
}

func getPkgName(d interface{}) string {
	_, name := path.Split(reflect.TypeOf(d).Elem().PkgPath())
	return name
}

func getTypeName(d interface{}) string {
	_, name := path.Split(reflect.TypeOf(d).Elem().Name())
	return name
}
