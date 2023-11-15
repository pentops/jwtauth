package jwks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/pquerna/cachecontrol/cacheobject"
	"gopkg.in/square/go-jose.v2"
)

type KeySource interface {
	Refresh(ctx context.Context) (time.Duration, error)
	Keys() []jose.JSONWebKey
}

type StaticKeySource struct {
	KeySet jose.JSONWebKeySet
}

func (ss *StaticKeySource) Keys() []jose.JSONWebKey {
	return ss.KeySet.Keys
}

func (ss *StaticKeySource) Refresh(ctx context.Context) (time.Duration, error) {
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
