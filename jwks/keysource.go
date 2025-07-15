package jwks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/pentops/log.go/log"
	"github.com/pquerna/cachecontrol/cacheobject"
	"gopkg.in/square/go-jose.v2"
)

type KeySource interface {
	Refresh(ctx context.Context) (time.Duration, error)
	Keys() []jose.JSONWebKey
	Name() string
}

type StaticKeySource struct {
	KeySet jose.JSONWebKeySet
}

func (ss *StaticKeySource) Keys() []jose.JSONWebKey {
	return ss.KeySet.Keys
}

func (ss *StaticKeySource) Name() string {
	return "static"
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

func NewHTTPKeySource(client *http.Client, url string) *HTTPKeySource {
	return &HTTPKeySource{
		url:    url,
		client: client,
		keyset: &jose.JSONWebKeySet{},
		lock:   sync.RWMutex{},
	}
}

func (ss *HTTPKeySource) Keys() []jose.JSONWebKey {
	ss.lock.RLock()
	defer ss.lock.RUnlock()
	if ss.keyset == nil {
		return nil
	}
	return ss.keyset.Keys
}

func (ss *HTTPKeySource) Name() string {
	return ss.url
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
		return 0, fmt.Errorf("parsing %s: %w", ss.url, err)
	}

	refreshTime := parseCacheControlHeader(res.Header.Get("Cache-Control"))

	keyIDs := []string{}
	for _, key := range keyset.Keys {
		keyIDs = append(keyIDs, key.KeyID)
	}
	slices.Sort(keyIDs)

	ss.lock.Lock()
	defer ss.lock.Unlock()
	changed := false
	if ss.keyset == nil || len(ss.keyset.Keys) != len(keyset.Keys) {
		changed = true
	} else {
		for i, key := range ss.keyset.Keys {
			if key.KeyID != keyset.Keys[i].KeyID {
				changed = true
				break
			}
		}
	}
	if changed {
		log.WithFields(ctx, map[string]any{
			"oldKeys": ss.keyset.Keys,
			"newKeys": keyIDs,
			"url":     ss.url,
		}).Info("JWKS Client Loaded New keys")
	}

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
