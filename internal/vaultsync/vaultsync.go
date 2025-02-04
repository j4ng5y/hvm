package vaultsync

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/hashicorp/vault-client-go"
	"github.com/rs/zerolog/log"
)

type (
	// Syncer is a struct that facilitates the syncing of secrets between two vaults.
	Syncer struct {
		cfg              *Config
		sourceVault      *vault.Client
		destinationVault *vault.Client
	}
)

// NewSyncer returns a new Syncer.
// Arguments:
//
//	src: *vault.Client - The source vault client instance.
//	dst: *vault.Client - The destination vault client instance.
//
// Returns:
//
//	*Syncer - A new Syncer instance.
func NewSyncer(config *Config) (*Syncer, error) {
	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	s := new(Syncer)

	src, err := s.initVault(config.SourceVault)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize source vault: %w", err)
	}

	dst, err := s.initVault(config.DestinationVault)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize destination vault: %w", err)
	}

	s.cfg = config
	s.sourceVault = src
	s.destinationVault = dst
	return s, nil
}

func (s *Syncer) initVault(cfg *Vault) (*vault.Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("vault config is nil")
	}

	var tkn string
	switch {
	case cfg.TokenCmd != "":
		cmd := strings.Split(cfg.TokenCmd, " ")
		b, err := exec.Command(cmd[0], cmd[1:]...).Output()
		if err != nil {
			return nil, fmt.Errorf("failed to execute token command: %w", err)
		}
		if bytes.HasPrefix(b, []byte("hvs.")) {
			tkn = string(bytes.TrimSpace(b))
		} else {
			return nil, fmt.Errorf("token command did not return a vault token")
		}
	case cfg.Token != "":
		tkn = cfg.Token
	default:
		return nil, fmt.Errorf("no token provided")
	}

	src, err := vault.New(
		vault.WithAddress(cfg.Address),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}
	if err := src.SetToken(tkn); err != nil {
		return nil, fmt.Errorf("failed to set vault token: %w", err)
	}
	return src, nil
}

// listSourcePath returns a list of all the secret keys in the given path/mount.
//
// Arguments:
//
//	ctx: context.Context - The context for the operation.
//	mount: string - The mount path of the source vault.
//	path: string - The path of the source vault to list.
//
// Returns:
//
//	[]string - A list of secret keys in the given path/mount.
//	error - An error if there was a problem listing the path.
func (s *Syncer) listSourcePath(ctx context.Context, mount, path string) ([]string, error) {
	var retVal []string

	log.Debug().Str("path", path).Str("mouth", mount).Msg("Listing source vault")

	// Unfortunately, there is no good way to batch out this initial indexing, so we just have to be careful on how we do it.
	l, err := s.sourceVault.List(ctx, mount+"/metadata/"+path, vault.WithMountPath(mount))
	if err != nil {
		return nil, fmt.Errorf("failed to list source path: %w", err)
	}

	if v, ok := l.Data["keys"].([]interface{}); ok {
		for _, vv := range v {
			retVal = append(retVal, vv.(string))
		}
	} else {
		return nil, fmt.Errorf("failed to list source path: vault returned an empty list")
	}

	return retVal, nil
}

// batchSync performs a batch sync of the given batch of secrets keys.
//
// Arguments:
//
//	ctx: context.Context - The context for the operation.
//	mount: string - The mount path of the source vault.
//	path: string - The path of the source vault to sync.
//	batch: []string - The batch of secret keys to sync.
//
// Returns: nothing
func (s *Syncer) batchSync(ctx context.Context, mount, path string, batch []string) {
	var wg sync.WaitGroup
	for _, item := range batch {
		wg.Add(1)
		go s.doSync(&wg, ctx, mount, path+item)
	}
	wg.Wait()
}

// doSync performs a sync of the given secret key.
//
// Arguments:
//
//	wg: *sync.WaitGroup - The wait group for the operation.
//	ctx: context.Context - The context for the operation.
//	mount: string - The mount path of the source vault.
//	path: string - The path of the source vault to sync.
//
// Returns: nothing
func (s *Syncer) doSync(wg *sync.WaitGroup, ctx context.Context, mount, path string) {
	defer wg.Done()

	log.Debug().Str("secret", path).Str("mount", mount).Msg("Syncing secret")

	srcResp, err := s.sourceVault.Read(ctx, mount+"/data/"+path, vault.WithMountPath(mount))
	if err != nil {
		log.Error().Err(err).Str("secret", path).Msg("Failed to get secret from source vault")
		return
	}

	if _, err := s.destinationVault.Write(ctx, mount+"/data/"+path, srcResp.Data, vault.WithMountPath(mount)); err != nil {
		log.Error().Err(err).Str("secret", path).Msg("Failed to write secret to destination vault")
		return
	}

	destResp, err := s.destinationVault.Read(ctx, mount+"/data/"+path, vault.WithMountPath(mount))
	if err != nil {
		log.Error().Err(err).Str("secret", path).Msg("Failed to get secret from destination vault")
		return
	}

	if s.eq(srcResp.Data["data"], destResp.Data["data"]) {
		log.Debug().Str("secret", path).Str("mount", mount).Msg("Secret synced")
	} else {
		log.Error().Str("secret", path).Str("mount", mount).Msg("Secrets do not match")
	}
}

func (s *Syncer) eq(src, dest interface{}) bool {
	srcb, err := json.Marshal(src)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal source secret")
		return false
	}

	destb, err := json.Marshal(dest)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal destination secret")
		return false
	}

	src256 := sha256.Sum256(srcb)
	dest256 := sha256.Sum256(destb)

	return src256 == dest256
}

// Sync performs a sync of the given path/mount.
//
// Arguments:
//
//	mount: string - The mount path of the source vault.
//	path: string - The path of the source vault to sync.
//	batchSize: int - The batch size to use for syncing so we
//	                 don't detonate the source vault with a
//	                 huge amount of reads
//
// Returns:
//
//	error - An error if there was a problem syncing the path.
func (s *Syncer) Sync() error {
	syncContext, syncCancel := context.WithCancel(context.Background())
	defer syncCancel()

	log.Info().Msg("Starting sync")

	srcList, err := s.listSourcePath(syncContext, s.cfg.SourceVault.Mount, s.cfg.SourceVault.Path)
	if err != nil {
		return fmt.Errorf("failed to list source path: %w", err)
	}

	for i := 0; i < len(srcList); i += s.cfg.BatchSize {
		end := i + s.cfg.BatchSize
		if end > len(srcList) {
			end = len(srcList)
		}
		batch := srcList[i:end]
		s.batchSync(syncContext, s.cfg.SourceVault.Mount, s.cfg.SourceVault.Path, batch)
	}

	log.Info().Msg("Sync complete")
	return nil
}
