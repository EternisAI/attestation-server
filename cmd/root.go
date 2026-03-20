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
	Use:           "attestation-server",
	Short:         "TEE attestation document server",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          runServer,
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
	rootCmd.Flags().String("build-info-path", "/etc/build-info.json", "path to build information file")
	rootCmd.Flags().String("endorsements-path", "/etc/endorsements.json", "path to endorsements URL list file")
	rootCmd.Flags().String("public-tls-cert-path", "", "path to public TLS certificate (PEM)")
	rootCmd.Flags().String("public-tls-key-path", "", "path to public TLS private key (PEM)")
	rootCmd.Flags().String("private-tls-cert-path", "", "path to private TLS certificate (PEM)")
	rootCmd.Flags().String("private-tls-key-path", "", "path to private TLS private key (PEM)")

	_ = viper.BindPFlag("bind_host", rootCmd.Flags().Lookup("host"))
	_ = viper.BindPFlag("bind_port", rootCmd.Flags().Lookup("port"))
	_ = viper.BindPFlag("log_format", rootCmd.Flags().Lookup("log-format"))
	_ = viper.BindPFlag("log_level", rootCmd.Flags().Lookup("log-level"))
	_ = viper.BindPFlag("build_info_path", rootCmd.Flags().Lookup("build-info-path"))
	_ = viper.BindPFlag("endorsements_path", rootCmd.Flags().Lookup("endorsements-path"))
	_ = viper.BindPFlag("public_tls_cert_path", rootCmd.Flags().Lookup("public-tls-cert-path"))
	_ = viper.BindPFlag("public_tls_key_path", rootCmd.Flags().Lookup("public-tls-key-path"))
	_ = viper.BindPFlag("private_tls_cert_path", rootCmd.Flags().Lookup("private-tls-cert-path"))
	_ = viper.BindPFlag("private_tls_key_path", rootCmd.Flags().Lookup("private-tls-key-path"))
}

func initConfig() {
	viper.SetDefault("bind_host", "0.0.0.0")
	viper.SetDefault("bind_port", 8187)
	viper.SetDefault("log_format", "json")
	viper.SetDefault("log_level", "info")
	viper.SetDefault("build_info_path", "/etc/build-info.json")
	viper.SetDefault("endorsements_path", "/etc/endorsements.json")

	_ = viper.BindEnv("bind_host", "BIND_HOST")
	_ = viper.BindEnv("bind_port", "BIND_PORT")
	_ = viper.BindEnv("log_format", "LOG_FORMAT")
	_ = viper.BindEnv("log_level", "LOG_LEVEL")
	_ = viper.BindEnv("build_info_path", "BUILD_INFO_PATH")
	_ = viper.BindEnv("endorsements_path", "ENDORSEMENTS_PATH")
	_ = viper.BindEnv("public_tls_cert_path", "PUBLIC_TLS_CERT_PATH")
	_ = viper.BindEnv("public_tls_key_path", "PUBLIC_TLS_KEY_PATH")
	_ = viper.BindEnv("private_tls_cert_path", "PRIVATE_TLS_CERT_PATH")
	_ = viper.BindEnv("private_tls_key_path", "PRIVATE_TLS_KEY_PATH")
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

	srv, err := app.NewServer(cfg, logger)
	if err != nil {
		logger.Error("failed to initialize server", "error", err)
		os.Exit(1)
	}
	if err := srv.Run(ctx); err != nil {
		logger.Error("server stopped", "error", err)
		return err
	}
	return nil
}
