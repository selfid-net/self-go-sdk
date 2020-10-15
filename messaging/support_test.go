package messaging

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/joinself/self-go-sdk/pkg/ntp"
	"github.com/joinself/self-go-sdk/pkg/siggraph"
	"github.com/square/go-jose"
	"golang.org/x/crypto/ed25519"
)

func setup(t *testing.T) (*testMessaging, *testPKI) {
	return &testMessaging{out: make(map[string][]byte)}, &testPKI{make(map[string][]json.RawMessage)}
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

func (c *testMessaging) Request(recipients []string, cid string, data []byte, timeout time.Duration) (string, []byte, error) {
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

func (c *testMessaging) ListConnections() ([]string, error) {
	var cs []string
	json.Unmarshal(c.in, &cs)
	return cs, nil
}

func (c *testMessaging) Command(command string, payload []byte) ([]byte, error) {
	c.out[command] = payload
	return c.in, c.sendError
}

type testPKI struct {
	history map[string][]json.RawMessage
}

func (c *testPKI) GetHistory(selfID string) ([]json.RawMessage, error) {
	history, ok := c.history[selfID]
	if !ok {
		return nil, errors.New("identity not found")
	}

	return history, nil
}

func (c *testPKI) addpk(selfID string, sk ed25519.PrivateKey, pk ed25519.PublicKey) {
	now := ntp.TimeFunc().Add(-(time.Hour * 356 * 24)).Unix()

	rpk, _, _ := ed25519.GenerateKey(rand.Reader)

	c.history[selfID] = []json.RawMessage{
		testop(sk, "1", &siggraph.Operation{
			Sequence:  0,
			Version:   "1.0.0",
			Previous:  "-",
			Timestamp: now,
			Actions: []siggraph.Action{
				{
					KID:           "1",
					DID:           "1",
					Type:          siggraph.TypeDeviceKey,
					Action:        siggraph.ActionKeyAdd,
					EffectiveFrom: now,
					Key:           base64.RawURLEncoding.EncodeToString(pk),
				},
				{
					KID:           "2",
					Type:          siggraph.TypeRecoveryKey,
					Action:        siggraph.ActionKeyAdd,
					EffectiveFrom: now,
					Key:           base64.RawURLEncoding.EncodeToString(rpk),
				},
			},
		}),
	}
}

func testop(sk ed25519.PrivateKey, kid string, op *siggraph.Operation) json.RawMessage {
	data, err := json.Marshal(op)
	if err != nil {
		panic(err)
	}

	opts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": kid,
		},
	}

	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: sk}, opts)
	if err != nil {
		panic(err)
	}

	jws, err := s.Sign(data)
	if err != nil {
		panic(err)
	}

	return json.RawMessage(jws.FullSerialize())
}
