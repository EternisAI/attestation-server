package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	app "github.com/eternisai/attestation-server/internal"
)

var rootCmd = &cobra.Command{
	Use:          "attestation-server",
	Short:        "TEE attestation document server",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:         runServer,
}

// Execute is the entry point called from main.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.Flags().String("host", "0.0.0.0", "bind host address")
	rootCmd.Flags().Int("port", 8187, "bind port number")
	rootCmd.Flags().String("log-format", "json", "log format (json, text)")
	rootCmd.Flags().String("log-level", "info", "log level (debug, info, warn, error)")

	_ = viper.BindPFlag("bind_host", rootCmd.Flags().Lookup("host"))
	_ = viper.BindPFlag("bind_port", rootCmd.Flags().Lookup("port"))
	_ = viper.BindPFlag("log_format", rootCmd.Flags().Lookup("log-format"))
	_ = viper.BindPFlag("log_level", rootCmd.Flags().Lookup("log-level"))
}

func initConfig() {
	viper.SetDefault("bind_host", "0.0.0.0")
	viper.SetDefault("bind_port", 8187)
	viper.SetDefault("log_format", "json")
	viper.SetDefault("log_level", "info")

	_ = viper.BindEnv("bind_host", "BIND_HOST")
	_ = viper.BindEnv("bind_port", "BIND_PORT")
	_ = viper.BindEnv("log_format", "LOG_FORMAT")
	_ = viper.BindEnv("log_level", "LOG_LEVEL")
}

func runServer(cmd *cobra.Command, args []string) error {
	cfg := app.LoadConfig()
	logger := app.NewLogger(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	go func() {
		select {
		case sig := <-sigCh:
			logger.Info("shutting down on signal", "signal", sig.String())
			cancel()
		case <-ctx.Done():
		}
	}()

	srv := app.NewServer(cfg, logger)
	if err := srv.Run(ctx); err != nil {
		logger.Error("server stopped", "error", err)
		return err
	}
	return nil
}
