package keys

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"gopkg.in/square/go-jose.v2"
)

func ParsePrivateKey(ctx context.Context, encKey string) (*jose.JSONWebKey, error) {
	decKey, err := base64.StdEncoding.DecodeString(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode jwk as base64: %v", err.Error())
	}

	privateKey := jose.JSONWebKey{}
	err = json.Unmarshal([]byte(decKey), &privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %v", err.Error())
	}

	return &privateKey, nil
}

func EncodeKey(ctx context.Context, key *jose.JSONWebKey) (string, error) {
	asJSON, err := key.MarshalJSON()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(asJSON), nil
}
