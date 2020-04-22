package fact

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

var cts = strings.Contains

func setup(t *testing.T) (*testResponder, Config) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	tr := testResponder{
		pk:   pk,
		path: "/v1/auth",
		keys: make(map[string][]byte),
	}

	return &tr, Config{
		SelfID:     "test",
		DeviceID:   "1",
		PrivateKey: sk,
		PKI:        &tr,
		Messaging:  &tr,
		Rest:       &tr,
	}
}

type testResponder struct {
	pk         ed25519.PublicKey
	keys       map[string][]byte
	path       string
	payload    []byte
	recipients []string
	request    []byte
	responder  func(recipients []string, data []byte) (string, []byte, error)
}

func (c *testResponder) Register(cid string) {
}

func (c *testResponder) Wait(cid string, timeout time.Duration) (string, []byte, error) {
	return c.responder(c.recipients, c.request)
}

func (c *testResponder) Request(recipients []string, cid string, data []byte) (string, []byte, error) {
	c.recipients = recipients
	return c.responder(recipients, data)
}

func (c *testResponder) Get(path string) ([]byte, error) {
	if path != c.path || cts(path, "unknown") {
		fmt.Println(path)
		return nil, errors.New("not found")
	}

	return c.payload, nil
}

func (c *testResponder) GetPublicKeys(selfID string) ([]byte, error) {
	keys, ok := c.keys[selfID]
	if !ok {
		fmt.Println(c.keys)
		fmt.Println(selfID)
		return nil, errors.New("identity not found")
	}

	return keys, nil
}

func (c *testResponder) addpk(selfID string, pk ed25519.PublicKey) {
	pkd := enc.EncodeToString(pk)
	c.keys[selfID] = []byte(`[{"id": 1, "key": "` + pkd + `"}]`)
}
