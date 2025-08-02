package jwks

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/pentops/log.go/log"
	"golang.org/x/sync/errgroup"
)

// JWKSManager merges multiple JWKS sources
type JWKSManager struct {
	servers   []KeySource
	jwksBytes []byte

	mutex     sync.RWMutex // Locks functions of the manager
	jwksMutex sync.RWMutex // Locks the keys

	initialLoad       chan error
	DefaultHTTPClient *http.Client

	running bool
}

func NewKeyManager(sources ...KeySource) *JWKSManager {
	ss := &JWKSManager{
		servers:   sources,
		jwksBytes: []byte(`{"keys":[]}`),
		DefaultHTTPClient: &http.Client{
			Timeout: time.Second * 5,
		},
		initialLoad: make(chan error),
	}

	return ss
}

func (km *JWKSManager) AddSources(source ...KeySource) {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	km.servers = append(km.servers, source...)
}

func (km *JWKSManager) AddSourceURLs(urls ...string) error {
	sources := make([]KeySource, 0, len(urls))
	for _, url := range urls {
		server := NewHTTPKeySource(km.DefaultHTTPClient, url)
		sources = append(sources, server)
	}

	km.AddSources(sources...)

	return nil
}

func keyIsValidForJWKS(key jose.JSONWebKey) error {
	if key.KeyID == "" {
		return fmt.Errorf("key has no key ID")
	}

	if !key.Valid() {
		return fmt.Errorf("key %s is not valid", key.KeyID)
	}

	if !key.IsPublic() {
		return fmt.Errorf("key %s is not public", key.KeyID)
	}

	return nil
}

func (km *JWKSManager) AddPublicKeys(keys ...jose.JSONWebKey) error {
	for idx, key := range keys {
		if err := keyIsValidForJWKS(key); err != nil {
			return fmt.Errorf("key %d: %w", idx, err)
		}
	}

	keySource := &StaticKeySource{
		KeySet: jose.JSONWebKeySet{
			Keys: keys,
		},
	}

	km.AddSources(keySource)

	return nil
}

// WaitForKeys blocks until the load of keys has completed at least once
// for each source.
func (km *JWKSManager) WaitForKeys(ctx context.Context) error {
	return <-km.initialLoad
}

// Run fetches once from each source, then refreshes the keys based on cache
// control headers. If the initial load fails repeatedly this will exit with an
// error
func (km *JWKSManager) Run(ctx context.Context) error {
	km.mutex.Lock()
	if km.running {
		km.mutex.Unlock()
		return fmt.Errorf("JWKSManager is already running")
	}

	km.running = true
	km.mutex.Unlock()

	log.Debug(ctx, "JWKS Running")
	initGroup := sync.WaitGroup{}

	eg, ctx := errgroup.WithContext(ctx)
	for _, server := range km.servers {
		initGroup.Add(1)
		eg.Go(func() error {
			var duration time.Duration
			var err error
			loadedOnce := false
			errorCount := 0
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(duration):
					duration, err = server.Refresh(ctx)
					if err != nil {
						log.WithError(ctx, err).Error("fetching JWKS")
						errorCount++
						if !loadedOnce && errorCount > 5 {
							return err
						} else {
							duration = time.Second * 5
						}
					} else {
						km.mergeKeys()
						if !loadedOnce {
							loadedOnce = true
							initGroup.Done()
						}
						errorCount = 0
					}
				}
			}
		})
	}

	go func() {
		initGroup.Wait()
		close(km.initialLoad)
	}()

	return eg.Wait()
}

func (km *JWKSManager) mergeKeys() {
	km.jwksMutex.Lock()
	defer km.jwksMutex.Unlock()

	keys := make([]jose.JSONWebKey, 0, 1)

	for _, server := range km.servers {
		keys = append(keys, server.Keys()...)
	}

	keySet := jose.JSONWebKeySet{
		Keys: keys,
	}

	keyBytes, err := json.Marshal(keySet)
	if err != nil {
		return
	}

	km.jwksBytes = keyBytes
}

func (km *JWKSManager) JWKS() []byte {
	km.jwksMutex.RLock()
	defer km.jwksMutex.RUnlock()

	return km.jwksBytes
}

func keysMatch(a, b jose.JSONWebKey) bool {
	if a.KeyID != b.KeyID {
		return false
	}

	if a.Algorithm != b.Algorithm {
		return false
	}

	thumbA, err := a.Thumbprint(crypto.SHA1)
	if err != nil {
		return false
	}

	thumbB, err := b.Thumbprint(crypto.SHA1)
	if err != nil {
		return false
	}

	if !bytes.Equal(thumbA, thumbB) {
		return false
	}
	return true
}
func (km *JWKSManager) GetKeys(keyID string) ([]jose.JSONWebKey, error) {
	km.mutex.RLock()
	defer km.mutex.RUnlock()

	keysByID := make(map[string]jose.JSONWebKey)

	for _, server := range km.servers {
		for _, key := range server.Keys() {
			if key.KeyID == keyID {
				if existingKey, exists := keysByID[key.KeyID]; exists {
					if !keysMatch(existingKey, key) {
						return nil, fmt.Errorf("key %s exists with different properties", key.KeyID)
					}
					continue
				}

				keysByID[key.KeyID] = key
			}
		}
	}

	return slices.Collect(maps.Values(keysByID)), nil
}

type KeySummary struct {
	Keys   []string `json:"keys"`
	Source string   `json:"source"`
}

// KeySummary is designed to be used in log messages for debugging exceptions
func (km *JWKSManager) KeyDebug() any {
	km.mutex.RLock()
	defer km.mutex.RUnlock()
	keys := make([]KeySummary, 0, 1)

	for _, server := range km.servers {
		serverKeys := server.Keys()
		keyIDs := make([]string, 0, len(serverKeys))

		for _, key := range serverKeys {
			keyIDs = append(keyIDs, key.KeyID)
		}

		keys = append(keys, KeySummary{
			Keys:   keyIDs,
			Source: server.Name(),
		})
	}

	return keys
}

// ServeJWKS serves the JWKS on the given address with basic plaintext configs,
// for use behind a load balancer etc. For more control, use ServeHTTP in your
// own server, or the JWKS() method into any other server
func (km *JWKSManager) ServeJWKS(ctx context.Context, addr string) error {
	if err := km.WaitForKeys(ctx); err != nil {
		return err
	}

	srv := http.Server{
		Addr:    addr,
		Handler: km,
	}

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	return srv.ListenAndServe()
}

func (km *JWKSManager) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/.well-known/jwks.json" {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	_, err := w.Write(km.JWKS())
	if err != nil {
		log.WithError(req.Context(), err).Error("Failed to write JWKS Response")
	}
}
