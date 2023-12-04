package grpcjwt

import (
	"context"
	"net/http"
	"strings"

	"github.com/pentops/log.go/log"
	"github.com/pentops/o5-runtime-sidecar/proxy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/square/go-jose.v2"
)

type JWKS interface {
	GetKeys(keyID string) ([]jose.JSONWebKey, error)
}

const (
	MissingAuthHeaderMessage  = "missing authorization header"
	InvalidAuthHeaderMessage  = "invalid authorization header, must begin with 'Bearer '"
	InvalidTokenFormatMessage = "invalid token format in authorization header, must be JWT"
	NoTrustedKeyMessage       = "A valid JWT was found, however it was not signed by any trusted key"

	VerifiedJWTHeader = "X-Verified-JWT"
)

func JWKSAuthFunc(jwks JWKS) proxy.AuthFunc {
	return func(ctx context.Context, req *http.Request) (map[string]string, error) {

		authHeader := req.Header.Get("Authorization")
		if authHeader == "" {
			return nil, status.Error(codes.Unauthenticated, MissingAuthHeaderMessage)
		}
		if !strings.HasPrefix(authHeader, "Bearer ") {
			return nil, status.Error(codes.Unauthenticated, InvalidAuthHeaderMessage)
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		sig, err := jose.ParseSigned(token)
		if err != nil {
			log.WithError(ctx, err).Error("parsing token")
			return nil, status.Error(codes.Unauthenticated, InvalidTokenFormatMessage)
		}

		var keyID string
		// find the first signature with a key id
		for _, sig := range sig.Signatures {
			if sig.Header.KeyID != "" {
				keyID = sig.Header.KeyID
				break
			}
		}

		if keyID == "" {
			return nil, status.Error(codes.Unauthenticated, InvalidTokenFormatMessage)
		}

		keys, err := jwks.GetKeys(keyID)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		if len(keys) != 1 {
			return nil, status.Error(codes.Unauthenticated, NoTrustedKeyMessage)
		}

		verifiedBytes, err := sig.Verify(keys[0])
		if err != nil {
			return nil, err
		}

		if verifiedBytes == nil {
			return nil, status.Error(codes.Unauthenticated, "invalid signature")
		}

		return map[string]string{
			VerifiedJWTHeader: string(verifiedBytes),
		}, nil
	}
}
