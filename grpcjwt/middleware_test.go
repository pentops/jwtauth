package grpcjwt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/pentops/log.go/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type testJWKS struct {
	keys []jose.JSONWebKey
}

func sign(t testing.TB, privateKey *jose.JSONWebKey, claims *jwt.Claims) string {
	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.EdDSA,
			Key:       privateKey.Key,
		},
		(&jose.SignerOptions{}).
			WithHeader(jose.HeaderKey("kid"), privateKey.KeyID),
	)

	if err != nil {
		t.Fatal(err.Error())
	}

	str, err := jwt.
		Signed(signer).
		Claims(claims).
		CompactSerialize()

	if err != nil {
		t.Fatal(err.Error())
	}

	return str
}

func testKey(t testing.TB) *jose.JSONWebKey {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err.Error())
	}

	k := &jose.JSONWebKey{
		Key:       privKey,
		KeyID:     uuid.NewString(),
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}
	return k
}

func (tj *testJWKS) GetKeys(keyID string) ([]jose.JSONWebKey, error) {
	out := make([]jose.JSONWebKey, 0)
	for _, key := range tj.keys {
		if key.KeyID == keyID {
			out = append(out, key)
		}
	}

	return out, nil
}

func codeError(t testing.TB, err error, code codes.Code, contains ...string) {
	t.Helper()
	if err == nil {
		t.Errorf("Expected error, got nil")
		return
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Errorf("Expected status error, got %v", err)
		return
	}
	if st.Code() != code {
		t.Errorf("Expected code %v, got %v", code, st.Code())
	}
	msg := st.Message()
	for _, c := range contains {
		if !strings.Contains(msg, c) {
			t.Errorf("Expected error to contain '%q', got '%q'", c, msg)
		}
	}
}
func reqWithHeaders(params ...string) *http.Request {
	rr := httptest.NewRequest("GET", "/thing", nil)
	if len(params)%2 != 0 {
		panic("params must be key value pairs")
	}

	for i := 0; i < len(params); i += 2 {
		rr.Header.Set(params[i], params[i+1])
	}

	return rr
}

func TestMiddleware(t *testing.T) {

	log.DefaultLogger = log.NewCallbackLogger(func(level string, msg string, attrs []slog.Attr) {
		fields := make(map[string]any, len(attrs))
		for _, attr := range attrs {
			fields[attr.Key] = attr.Value.Any()
		}
		t.Logf("%s: %s   %v", level, msg, fields)
	})

	mock := &testJWKS{}
	authFunc := JWKSAuthFunc(mock)

	ctx := context.Background()

	// No Key
	_, err := authFunc(ctx, reqWithHeaders())
	codeError(t, err, codes.Unauthenticated, MissingAuthHeaderMessage)

	// Bad Header Format
	_, err = authFunc(ctx, reqWithHeaders("Authorization", "Foobar"))
	codeError(t, err, codes.Unauthenticated, InvalidAuthHeaderMessage)

	// Bad Key Format
	_, err = authFunc(ctx, reqWithHeaders("Authorization", "Bearer Foobar"))
	codeError(t, err, codes.Unauthenticated, InvalidTokenFormatMessage)

	key := testKey(t)

	// Good Key
	claims := &jwt.Claims{
		Issuer:  "me",
		Subject: "you",
	}
	signed := sign(t, key, claims)

	// Before trusting
	_, err = authFunc(ctx, reqWithHeaders("Authorization", "Bearer "+signed))
	codeError(t, err, codes.Unauthenticated, NoTrustedKeyMessage)

	// Now trust it
	mock.keys = append(mock.keys, key.Public())
	header, err := authFunc(ctx, reqWithHeaders("Authorization", "Bearer "+signed))
	if err != nil {
		t.Fatal(err.Error())
	}

	verified, ok := header[VerifiedJWTHeader]
	if !ok {
		t.Fatal("Expected verified header")
	}

	t.Log(verified)
	gotClaim := &jwt.Claims{}
	if err := json.Unmarshal([]byte(verified), gotClaim); err != nil {
		t.Fatal(err.Error())
	}

	if !reflect.DeepEqual(gotClaim, claims) {
		t.Errorf("Expected claims %v, got %v", claims, gotClaim)
	}
}
