package main

import (
	"os"

	"github.com/j4ng5y/hvm/cmd"
	"github.com/rs/zerolog"
)

var log = zerolog.New(os.Stderr).With().Timestamp().Caller().Logger()

func main() {
	if err := cmd.CLI(); err != nil {
		log.Fatal().Err(err).Msg("Failed to run CLI")
	}
}
