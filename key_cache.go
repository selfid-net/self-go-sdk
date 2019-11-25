package selfsdk

import (
	"golang.org/x/crypto/ed25519"
)

type keyCache struct {
	client *Client
	keys   map[string][]ed25519.PublicKey
}

func newKeyCache(c *Client) *keyCache {
	return &keyCache{
		client: c,
		keys:   make(map[string][]ed25519.PublicKey),
	}
}

func (k *keyCache) get(selfID string) ([]ed25519.PublicKey, error) {
	keys, ok := k.keys[selfID]
	if ok {
		return keys, nil
	}

	if len(selfID) > 10 {
		return k.getApp(selfID)
	}

	return k.getIdentity(selfID)
}

func (k *keyCache) getApp(selfID string) ([]ed25519.PublicKey, error) {
	identity, err := k.client.GetIdentity(selfID)
	if err != nil {
		return nil, err
	}

	for _, key := range identity.PublicKeys {
		data, err := Decode(key.Key)
		if err != nil {
			return nil, err
		}

		k.keys[selfID] = append(k.keys[selfID], ed25519.PublicKey(data))
	}

	return k.keys[selfID], nil
}

func (k *keyCache) getIdentity(selfID string) ([]ed25519.PublicKey, error) {
	app, err := k.client.GetApp(selfID)
	if err != nil {
		return nil, err
	}

	for _, key := range app.PublicKeys {
		data, err := Decode(key.Key)
		if err != nil {
			return nil, err
		}

		k.keys[selfID] = append(k.keys[selfID], ed25519.PublicKey(data))
	}

	return k.keys[selfID], nil
}
