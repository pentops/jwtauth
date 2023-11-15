package jwks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/pentops/log.go/log"
	"golang.org/x/sync/errgroup"
	"gopkg.in/square/go-jose.v2"
)

// JWKSManager merges multiple JWKS sources
type JWKSManager struct {
	servers           []KeySource
	jwksBytes         []byte
	mutex             sync.RWMutex
	jwksMutex         sync.RWMutex
	initialLoad       chan error
	DefaultHTTPClient *http.Client
}

func NewKeyManager(sources ...KeySource) *JWKSManager {
	ss := &JWKSManager{
		servers:   sources,
		jwksBytes: []byte(`{"keys":[]}`),
		DefaultHTTPClient: &http.Client{
			Timeout: time.Second * 5,
		},
	}
	return ss
}

func (km *JWKSManager) AddSources(source ...KeySource) {
	km.mutex.RLock()
	defer km.mutex.RUnlock()
	km.servers = append(km.servers, source...)
}

func (km *JWKSManager) AddSourceFromURLs(urls ...string) error {
	sources := make([]KeySource, 0, len(urls))
	for _, url := range urls {
		server := &HTTPKeySource{
			client: km.DefaultHTTPClient,
			url:    url,
		}
		sources = append(sources, server)
	}
	km.AddSources(sources...)
	return nil
}

func keyIsValidForJWKS(key jose.JSONWebKey) error {
	if key.KeyID == "" {
		return fmt.Errorf("Key has no key ID")
	}
	if !key.Valid() {
		return fmt.Errorf("Key %s is not valid", key.KeyID)
	}
	if !key.IsPublic() {
		return fmt.Errorf("Key %s is not public", key.KeyID)
	}
	return nil
}

func (km *JWKSManager) AddKeys(keys ...jose.JSONWebKey) error {
	for idx, key := range keys {
		if err := keyIsValidForJWKS(key); err != nil {
			return fmt.Errorf("Key %d: %w", idx, err)
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

func (km *JWKSManager) logError(ctx context.Context, err error) {
	log.WithError(ctx, err).Error("Failed to load JWKS")
}

// Run fetches once from each source, then refreshes the keys based on cache
// control headers. If the initial load fails repeatedly this will exit with an
// error
func (km *JWKSManager) Run(ctx context.Context) error {
	initGroup := sync.WaitGroup{}
	eg, ctx := errgroup.WithContext(ctx)
	for _, server := range km.servers {
		server := server
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
						km.logError(ctx, err)
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
		serverKeys := server.Keys()
		keys = append(keys, serverKeys...)
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

func (km *JWKSManager) GetKeys(keyID string) ([]jose.JSONWebKey, error) {
	km.mutex.RLock()
	defer km.mutex.RUnlock()
	keys := make([]jose.JSONWebKey, 0, 1)

	for _, server := range km.servers {
		serverKeys := server.Keys()
		for _, key := range serverKeys {
			if key.KeyID == keyID {
				keys = append(keys, key)
			}
		}
	}

	return keys, nil
}

// ServeJWKS serves the JWKS on the given address with basic plaintext configs,
// for use behind a load balancer etc. For more control, use ServeHTTP in your
// own server, or the JWKS() method into any other server
func (km *JWKSManager) ServeJWKS(ctx context.Context, addr string) error {
	<-km.initialLoad
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

	jwksBytes := km.JWKS()
	_, err := w.Write(jwksBytes)
	if err != nil {
		log.WithError(req.Context(), err).Error("Failed to write JWKS Response")
	}
}
