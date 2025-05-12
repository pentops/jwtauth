package keys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"

	"github.com/google/uuid"
	"gopkg.in/square/go-jose.v2"
)

const (
	KeyUseSigner = "sig"
)

func GeneratePrivateKey(ctx context.Context) (*jose.JSONWebKey, error) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	k := &jose.JSONWebKey{
		Key:       privKey,
		KeyID:     uuid.NewString(),
		Algorithm: string(jose.EdDSA),
		Use:       KeyUseSigner,
	}

	return k, nil
}
