package authentication

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/square/go-jose"
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
	pk        ed25519.PublicKey
	keys      map[string][]byte
	path      string
	payload   []byte
	req       map[string]string
	responder func(req map[string]string) (string, []byte, error)
}

func (c *testResponder) Request(recipients []string, cid string, data []byte) (string, []byte, error) {
	var req map[string]string

	jws, err := jose.ParseSigned(string(data))
	if err != nil {
		return "", nil, err
	}

	err = json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &req)
	if err != nil {
		return "", nil, err
	}

	return c.responder(req)
}

func (c *testResponder) Register(cid string) {
}

func (c *testResponder) Wait(cid string, timeout time.Duration) (string, []byte, error) {
	return c.responder(c.req)
}

type testRestTransport struct {
	path    string
	payload []byte
}

func (c *testResponder) Send(recipients []string, plaintext []byte) error {
	return nil
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
