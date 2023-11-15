package jwks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/pentops/log.go/log"
	"github.com/pquerna/cachecontrol/cacheobject"
	"golang.org/x/sync/errgroup"
	"gopkg.in/square/go-jose.v2"
)

type KeySource interface {
	Refresh(ctx context.Context) (time.Duration, error)
	Keys() []jose.JSONWebKey
}

// JWKSManager merges multiple JWKS sources
type JWKSManager struct {
	servers     []KeySource
	jwksBytes   []byte
	mutex       sync.RWMutex
	jwksMutex   sync.RWMutex
	initialLoad chan error
}

func NewKeyManager(sources ...KeySource) *JWKSManager {
	ss := &JWKSManager{
		servers:   sources,
		jwksBytes: []byte(`{"keys":[]}`),
	}
	return ss
}

func NewKeyManagerFromURLs(urls ...string) (*JWKSManager, error) {
	servers := make([]KeySource, len(urls))

	client := &http.Client{
		Timeout: time.Second * 5,
	}
	for idx, url := range urls {
		server := &HTTPKeySource{
			client: client,
			url:    url,
		}
		servers[idx] = server
	}

	ss := &JWKSManager{
		servers:     servers,
		jwksBytes:   []byte(`{"keys":[]}`),
		initialLoad: make(chan error),
	}

	return ss, nil
}

// WaitForKeys blocks until the load of keys has completed at least once
// for each source.
func (km *JWKSManager) WaitForKeys(ctx context.Context) error {
	return <-km.initialLoad
}

func (km *JWKSManager) logError(ctx context.Context, err error) {
	log.WithError(ctx, err).Error("Failed to load JWKS")
}

// ServeJWKS serves the JWKS on the given address with basic plaintext configs,
// for use behind a load balancer etc. For more control, use ServeHTTP in your
// own server, or the JWKS() method into any other server
func (km *JWKSManager) ServeJWKS(ctx context.Context, addr string) error {
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

func (km *JWKSManager) AddSource(source KeySource) {
	km.mutex.RLock()
	defer km.mutex.RUnlock()
	km.servers = append(km.servers, source)
}

type DirectKeySource struct {
	KeySet jose.JSONWebKeySet
}

func (ss *DirectKeySource) Keys() []jose.JSONWebKey {
	return ss.KeySet.Keys
}

func (ss *DirectKeySource) Refresh(ctx context.Context) (time.Duration, error) {
	return time.Hour, nil
}

type HTTPKeySource struct {
	keyset *jose.JSONWebKeySet
	url    string
	client *http.Client
	lock   sync.RWMutex
}

func (ss *HTTPKeySource) Keys() []jose.JSONWebKey {
	ss.lock.RLock()
	defer ss.lock.RUnlock()
	return ss.keyset.Keys
}

func (ss *HTTPKeySource) Refresh(ctx context.Context) (time.Duration, error) {
	req, err := http.NewRequest("GET", ss.url, nil)
	if err != nil {
		return 0, err
	}

	res, err := ss.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("GET %s: %w", ss.url, err)
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("GET %s: %s", ss.url, res.Status)
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return 0, fmt.Errorf("GET %s: %w", ss.url, err)
	}

	keyset := &jose.JSONWebKeySet{}

	if err := json.Unmarshal(bodyBytes, keyset); err != nil {
		return 0, fmt.Errorf("Parsing %s: %w", ss.url, err)
	}

	refreshTime := parseCacheControlHeader(res.Header.Get("Cache-Control"))

	ss.lock.Lock()
	defer ss.lock.Unlock()
	ss.keyset = keyset
	return refreshTime, nil
}

func parseCacheControlHeader(raw string) time.Duration {
	respDir, err := cacheobject.ParseResponseCacheControl(raw)
	if err != nil || respDir.NoCachePresent || respDir.NoStore || respDir.PrivatePresent {
		return time.Second * 30
	}
	if respDir.MaxAge > 0 {
		return time.Duration(respDir.MaxAge) * time.Second
	}

	return time.Second * 30
}
