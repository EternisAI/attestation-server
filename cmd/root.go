package cmd

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	app "github.com/eternisai/attestation-server/internal"
)

var cfgFile string

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
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	cobra.OnInitialize(initConfig)

	rootCmd.Flags().StringVarP(&cfgFile, "config-file", "c", "", "path to config file (default: ./config/config.toml, ./config.toml)")
	rootCmd.Flags().String("log-format", "json", "log format (json, text)")
	rootCmd.Flags().String("log-level", "info", "log level (debug, info, warn, error)")

	_ = viper.BindPFlag("log.format", rootCmd.Flags().Lookup("log-format"))
	_ = viper.BindPFlag("log.level", rootCmd.Flags().Lookup("log-level"))
}

func initConfig() {
	viper.SetConfigType("toml")

	// Defaults
	viper.SetDefault("log.format", "json")
	viper.SetDefault("log.level", "info")
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.port", 8187)
	viper.SetDefault("paths.build_info", "/etc/build-info.json")
	viper.SetDefault("paths.endorsements", "/etc/endorsements.json")
	viper.SetDefault("report.evidence.nitronsm", false)
	viper.SetDefault("report.evidence.nitrotpm", false)
	viper.SetDefault("report.evidence.sevsnp", false)

	// Explicit environment variable bindings (avoids AutomaticEnv underscore ambiguity)
	_ = viper.BindEnv("log.format", "ATTESTATION_SERVER_LOG_FORMAT")
	_ = viper.BindEnv("log.level", "ATTESTATION_SERVER_LOG_LEVEL")
	_ = viper.BindEnv("server.host", "ATTESTATION_SERVER_SERVER_HOST")
	_ = viper.BindEnv("server.port", "ATTESTATION_SERVER_SERVER_PORT")
	_ = viper.BindEnv("paths.build_info", "ATTESTATION_SERVER_PATHS_BUILD_INFO")
	_ = viper.BindEnv("paths.endorsements", "ATTESTATION_SERVER_PATHS_ENDORSEMENTS")
	_ = viper.BindEnv("tls.public.cert_path", "ATTESTATION_SERVER_TLS_PUBLIC_CERT_PATH")
	_ = viper.BindEnv("tls.public.key_path", "ATTESTATION_SERVER_TLS_PUBLIC_KEY_PATH")
	_ = viper.BindEnv("tls.private.cert_path", "ATTESTATION_SERVER_TLS_PRIVATE_CERT_PATH")
	_ = viper.BindEnv("tls.private.key_path", "ATTESTATION_SERVER_TLS_PRIVATE_KEY_PATH")
	_ = viper.BindEnv("report.evidence.nitronsm", "ATTESTATION_SERVER_REPORT_EVIDENCE_NITRONSM")
	_ = viper.BindEnv("report.evidence.nitrotpm", "ATTESTATION_SERVER_REPORT_EVIDENCE_NITROTPM")
	_ = viper.BindEnv("report.evidence.sevsnp", "ATTESTATION_SERVER_REPORT_EVIDENCE_SEVSNP")
	_ = viper.BindEnv("report.user_data.env", "ATTESTATION_SERVER_REPORT_USER_DATA_ENV")

	// Config file resolution: flag > env var > fallback paths
	explicit := true
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else if envCfg := os.Getenv("ATTESTATION_SERVER_CONFIG_FILE"); envCfg != "" {
		viper.SetConfigFile(envCfg)
	} else {
		explicit = false
		viper.SetConfigName("config")
		viper.AddConfigPath("./config")
		viper.AddConfigPath(".")
	}

	if err := viper.ReadInConfig(); err != nil {
		if explicit {
			slog.Error("error reading config file", "error", err)
			os.Exit(1)
		}
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			slog.Error("error reading config file", "error", err)
			os.Exit(1)
		}
	}
}

func runServer(cmd *cobra.Command, args []string) error {
	cfg, err := app.LoadConfig()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	logger := app.NewLogger(cfg)

	if f := viper.ConfigFileUsed(); f != "" {
		logger.Info("loaded config file", "path", f)
	}

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
