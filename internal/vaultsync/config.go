package vaultsync

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

type (
	Config struct {
		BatchSize        int    `mapstructure:"batchSize"`
		SourceVault      *Vault `mapstructure:"srcVault"`
		DestinationVault *Vault `mapstructure:"destVault"`
	}

	Vault struct {
		Address  string `mapstructure:"addr"`
		Token    string `mapstructure:"token"`
		TokenCmd string `mapstructure:"tokenCmd"`
		Mount    string `mapstructure:"mount"`
		Path     string `mapstructure:"path"`
	}
)

func NewConfig(v *viper.Viper) (*Config, error) {
	c := new(Config)

	if err := v.Unmarshal(c); err != nil {
		log.Error().Err(err).Msg("failed to unmarshal config")
		return nil, err
	}

	return c, nil
}
