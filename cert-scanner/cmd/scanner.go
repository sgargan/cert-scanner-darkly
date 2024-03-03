package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sgargan/cert-scanner-darkly/config"
	"github.com/sgargan/cert-scanner-darkly/metrics"
	"github.com/sgargan/cert-scanner-darkly/scanner"
	"github.com/sgargan/cert-scanner-darkly/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/exp/slog"
)

var configPath string
var LogExit = logExit
var RunScan = scanner.PerformScan

type ScanCommand struct {
	cobra.Command
	interval time.Duration
	timeout  time.Duration
}

func CreateScanCommand() *ScanCommand {
	cmd := &cobra.Command{
		Use: "scan",
		Run: Run,
	}

	configureDefaultFlags(cmd)
	if err := config.LoadConfiguration(); err != nil {
		LogExit("error parsing configuration", "err", err)
	}

	return &ScanCommand{
		Command: *cmd,
	}
}

func Run(cmd *cobra.Command, args []string) {
	server := metrics.ConfigureMetrics(viper.GetInt("metrics.port"))
	if err := server.Start(); err != nil {
		logExit("error stopping metrics server", "err", err)
	}

	if viper.GetBool(config.Repeated) {
		repeatedly()
	} else {
		once()
	}

	if err := server.Stop(); err != nil {
		logExit("error stopping metrics server", "err", err)
	}
}

func repeatedly() {
	ctx, _ := signal.NotifyContext(context.Background(), syscall.SIGKILL)
	interval := viper.GetDuration(config.Interval)
	ticker := time.NewTicker(interval)
	running := false
	scans := 0
	for {
		if !running {
			scans += 1
			running = true
			slog.Info("running scan", "scans", scans)
			scan(ctx)
			slog.Debug("scan complete, waiting for interval before next scan", "scans", scans, "interval", interval.String())
			running = false
		} else {
			slog.Info("previous scan is still running", "scans", scans)
		}

		select {
		case <-ticker.C:
			slog.Debug("waited for interval after scan", "scans", scans, "interval", interval.String())
		case <-ctx.Done():
			slog.Info("context was cancelled, exiting", "scans", scans)
			return
		}
	}
}

func once() {
	slog.Info("running standalone scan")
	scan(context.Background())
}

func scan(ctx context.Context) {
	timeout := viper.GetDuration(config.Timeout)
	if timeout != 0 {
		ctx, _ = utils.CreateSignalledContextWithContext(ctx, timeout, syscall.SIGKILL)
	}
	scanner.PerformScan(ctx)
}

func configureDefaultFlags(cmd *cobra.Command) {
	persistentFlags := cmd.PersistentFlags()
	persistentFlags.StringVarP(&configPath, "config", "c", "./cert-scanner.yml", "config file (default is ~/.config/cert-scanner.yml)")
	persistentFlags.BoolP("debug", "d", false, "Use debug logging mode")
	viper.BindPFlag("debug", persistentFlags.Lookup("debug"))
	viper.BindPFlag("config", persistentFlags.Lookup("config"))
	cmd.ParseFlags(os.Args[1:])
}

func logExit(message string, tags ...any) {
	slog.Error(message, tags...)
	os.Exit(1)
}
