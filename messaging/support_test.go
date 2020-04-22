package messaging

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/square/go-jose"
	"golang.org/x/crypto/ed25519"
)

func setup(t *testing.T) (*testMessaging, *testPKI) {
	return &testMessaging{out: make(map[string][]byte)}, &testPKI{make(map[string][]byte)}
}

type testMessaging struct {
	recipients []string
	sender     string
	senderpk   ed25519.PublicKey
	in         []byte
	out        map[string][]byte
	responder  func(r map[string]string) (string, []byte, error)
	sendError  error
}

func (c *testMessaging) Send(recipients []string, data []byte) error {
	c.in = data
	return c.sendError
}

func (c *testMessaging) Request(recipients []string, cid string, data []byte) (string, []byte, error) {
	if c.responder == nil {
		return "", nil, errors.New("request timeout")
	}

	jws, err := jose.ParseSigned(string(data))
	if err != nil {
		return "", nil, err
	}

	payload, err := jws.Verify(c.senderpk)
	if err != nil {
		return "", nil, err
	}

	var req map[string]string

	err = json.Unmarshal(payload, &req)
	if err != nil {
		return "", nil, err
	}

	return c.responder(req)
}

func (c *testMessaging) Subscribe(msgType string, sub func(sender string, payload []byte)) {
	resp, ok := c.out[msgType]
	if ok {
		sub(c.sender, resp)
	}
}

func (c *testMessaging) Command(command string, payload []byte) ([]byte, error) {
	c.out[command] = payload
	return c.in, c.sendError
}

type testPKI struct {
	keys map[string][]byte
}

func (c *testPKI) GetPublicKeys(selfID string) ([]byte, error) {
	keys, ok := c.keys[selfID]
	if !ok {
		return nil, errors.New("identity not found")
	}

	return keys, nil
}

func (c *testPKI) addpk(selfID string, pk ed25519.PublicKey) {
	pkd := enc.EncodeToString(pk)
	c.keys[selfID] = []byte(`[{"id": 1, "key": "` + pkd + `"}]`)
}
