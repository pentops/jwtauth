package main

import (
	"context"
	"fmt"

	"github.com/pentops/jwtauth/jwks"
	"github.com/pentops/jwtauth/keys"
	"github.com/pentops/runner"
	"github.com/pentops/runner/commander"
)

var Version = "0.0.0"

func main() {
	cmdGroup := commander.NewCommandSet()

	cmdGroup.Add("serve", commander.NewCommand(runServer))
	cmdGroup.Add("generate-private-key", commander.NewCommand(runGeneratePrivateKey))

	cmdGroup.RunMain("jwks", Version)
}

func runGeneratePrivateKey(ctx context.Context, cfg struct{}) error {
	key, err := keys.GeneratePrivateKey(ctx)
	if err != nil {
		return err
	}

	keyString, err := keys.EncodeKey(ctx, key)
	if err != nil {
		return err
	}

	fmt.Println(string(keyString))

	return nil
}

func runServer(ctx context.Context, cfg struct {
	JWKSAddr     string   `env:"JWKS_ADDR" default:":8081"`
	PrivateKey   string   `env:"PRIVATE_KEY" required:"false"`
	UpstreamJWKS []string `env:"UPSTREAM_JWKS" default:""`
}) error {
	manager := jwks.NewKeyManager()

	if len(cfg.UpstreamJWKS) == 0 && cfg.PrivateKey == "" {
		return fmt.Errorf("no upstream JWKS URLs or private key provided")
	}

	err := manager.AddSourceURLs(cfg.UpstreamJWKS...)
	if err != nil {
		return fmt.Errorf("failed to add source URLs: %w", err)
	}

	if cfg.PrivateKey != "" {
		privateKey, err := keys.ParsePrivateKey(ctx, cfg.PrivateKey)
		if err != nil {
			return err
		}

		publicKey := privateKey.Public()

		err = manager.AddPublicKeys(publicKey)
		if err != nil {
			return fmt.Errorf("failed to add public keys: %w", err)
		}
	}

	runGroup := runner.NewGroup(runner.WithCancelOnSignals())
	runGroup.Add("jwks-fetcher", manager.Run)
	runGroup.Add("jwks-server", func(ctx context.Context) error {
		return manager.ServeJWKS(ctx, cfg.JWKSAddr)
	})

	return runGroup.Run(ctx)
}
