package jwks

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pentops/log.go/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type Verifier struct {
	ValidAudiences []string
	ValidIssuers   []string
	SigningKeys    jose.JSONWebKeySet
}

func (ss *Verifier) Verify(ctx context.Context, rawKey string, into any) error {
	sig, err := jose.ParseSigned(rawKey)
	if err != nil {
		return status.Error(codes.Unauthenticated, "Invalid JWT")
	}

	var kid string
	headers := make([]jose.Header, len(sig.Signatures))
	for i, signature := range sig.Signatures {
		headers[i] = signature.Header
		if signature.Header.KeyID != "" {
			kid = signature.Header.KeyID
		}
	}

	publicKey := ss.SigningKeys.Key(kid)
	if publicKey == nil {
		return status.Error(codes.Unauthenticated, "Unknown JWT Signing Key")
	}

	var verifiedBytes []byte

	verifiedBytes, err = sig.Verify(publicKey)
	if err != nil {
		return status.Error(codes.Unauthenticated, "Invalid JWT")
	}

	claim := &jwt.Claims{}
	if err := json.Unmarshal(verifiedBytes, claim); err != nil {
		log.WithError(ctx, err).Error("Failed to unmarshal claim (primary)")
		return status.Errorf(codes.Unauthenticated, "Bad Auth")
	}

	if claim.Expiry.Time().Before(time.Now()) {
		return status.Errorf(codes.Unauthenticated, "JWT is Expired")
	}

	if err := json.Unmarshal(verifiedBytes, into); err != nil {
		log.WithError(ctx, err).Error("Failed to unmarshal claim (extended)")
		return status.Errorf(codes.Unauthenticated, "Bad Auth")
	}

	return nil
}
