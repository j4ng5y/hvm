package cmd

import (
	"os"

	"github.com/j4ng5y/hvm/internal/vaultsync"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	version = "dev"
	rootCmd = &cobra.Command{
		Use:     "hvm",
		Short:   "Hashicorp Vault Migrator",
		Version: version,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cmd.Help(); err != nil {
				log.Error().Err(err).Msg("Failed to show help")
			}
		},
	}
	initCmd = &cobra.Command{
		Use:   "init",
		Short: "Initialize the Hashicorp Vault Migrator",
		Run:   initFunc,
	}
	runCmd = &cobra.Command{
		Use:   "run",
		Short: "Run the Hashicorp Vault Migrator",
		Run:   runFunc,
	}
	log = zerolog.New(os.Stderr).With().Timestamp().Caller().Logger()
	v   = viper.New()
)

func init() {
	rootCmd.AddCommand(initCmd, runCmd)

	initCmd.Flags().IntP("batch_size", "b", 100, "The batch size")

	initCmd.Flags().StringP("source_vault_addr", "a", "http://localhost:8200", "The source vault address")
	initCmd.Flags().StringP("target_vault_addr", "A", "http://localhost:8201", "The target vault address")
	initCmd.Flags().StringP("source_token", "t", "", "The source vault token")
	initCmd.Flags().String("source_token_command", "", "The source vault token command")
	initCmd.MarkFlagsMutuallyExclusive("source_token", "source_token_command")
	initCmd.Flags().StringP("target_token", "T", "", "The target vault token")
	initCmd.Flags().String("target_token_command", "", "The target vault token command")
	initCmd.MarkFlagsMutuallyExclusive("target_token", "target_token_command")
	initCmd.Flags().StringP("source_secret_path", "p", "path/to/my/secret", "The source vault secret path")
	initCmd.Flags().StringP("target_secret_path", "P", "", "The target vault secret path if you wish to override it")
	initCmd.Flags().StringP("source_secret_mount", "m", "secret", "The source vault secret mount")
	initCmd.Flags().StringP("target_secret_mount", "M", "", "The target vault secret mount if you with to override it")

	rootCmd.PersistentFlags().StringP("config_file", "f", "./config.yaml", "The config file")
	rootCmd.PersistentFlags().String("log_level", "info", "The log level")
}

func initFunc(cmd *cobra.Command, args []string) {
	cfgFile, err := cmd.Parent().PersistentFlags().GetString("config_file")
	if err != nil {
		log.Error().Err(err).Msg("Failed to get config file")
	}
	v.SetConfigFile(cfgFile)
	v.SetConfigType("yaml")

	batchSize, err := cmd.Flags().GetInt("batch_size")
	if err != nil {
		log.Error().Err(err).Msg("Failed to get batch size")
	}

	if batchSize != 0 {
		v.Set("batchSize", batchSize)
	}

	if cmd.Flag("source_vault_addr").Value.String() != "" {
		v.Set("srcVault.addr", cmd.Flag("source_vault_addr").Value.String())
	}
	switch {
	case cmd.Flag("source_token").Value.String() != "":
		v.Set("srcVault.token", cmd.Flag("source_token").Value.String())
	case cmd.Flag("source_token_command").Value.String() != "":
		v.Set("srcVault.tokenCmd", cmd.Flag("source_token_command").Value.String())
	default:
		log.Fatal().Msg("You must specify either a token or a token command")
	}
	if cmd.Flag("source_secret_path").Value.String() != "" {
		v.Set("srcVault.path", cmd.Flag("source_secret_path").Value.String())
	}
	if cmd.Flag("source_secret_mount").Value.String() != "" {
		v.Set("srcVault.mount", cmd.Flag("source_secret_mount").Value.String())
	}
	if cmd.Flag("target_vault_addr").Value.String() != "" {
		v.Set("destVault.addr", cmd.Flag("target_vault_addr").Value.String())
	}
	switch {
	case cmd.Flag("target_token").Value.String() != "":
		v.Set("destVault.token", cmd.Flag("target_token").Value.String())
	case cmd.Flag("target_token_command").Value.String() != "":
		v.Set("destVault.tokenCmd", cmd.Flag("target_token_command").Value.String())
	default:
		log.Fatal().Msg("You must specify either a token or a token command")
	}
	if cmd.Flag("target_secret_path").Value.String() != "" {
		v.Set("destVault.path", cmd.Flag("target_secret_path").Value.String())
	}
	if cmd.Flag("target_secret_mount").Value.String() != "" {
		v.Set("destVault.mount", cmd.Flag("target_secret_mount").Value.String())
	}
	if err := v.WriteConfig(); err != nil {
		log.Error().Err(err).Msg("Failed to write config")
	}
}

func runFunc(cmd *cobra.Command, args []string) {
	v.SetConfigFile(cmd.Flag("config_file").Value.String())
	if err := v.ReadInConfig(); err != nil {
		log.Error().Err(err).Msg("Failed to read config")
	}

	var lvl zerolog.Level
	lvl, err := zerolog.ParseLevel(cmd.Flag("log_level").Value.String())
	if err != nil {
		log.Error().Err(err).Msg("Failed to parse log level, defaulting to info")
		lvl = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(lvl)

	cfg, err := vaultsync.NewConfig(v)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create config")
	}

	syncer, err := vaultsync.NewSyncer(cfg)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create syncer")
	}

	if err := syncer.Sync(); err != nil {
		log.Error().Err(err).Msg("Failed to sync")
	}
}

func CLI() error {
	return rootCmd.Execute()
}
