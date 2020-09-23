package authentication

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/joinself/self-go-sdk/pkg/ntp"
	"github.com/joinself/self-go-sdk/pkg/siggraph"
	"github.com/square/go-jose"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

var cts = strings.Contains

func setup(t *testing.T) (*testResponder, Config) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	tr := testResponder{
		pk:      pk,
		path:    "/v1/auth",
		history: make(map[string][]json.RawMessage),
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
	history   map[string][]json.RawMessage
	path      string
	payload   []byte
	req       map[string]string
	responder func(req map[string]string) (string, []byte, error)
}

func (c *testResponder) Request(recipients []string, cid string, data []byte, timeout time.Duration) (string, []byte, error) {
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

func (c *testResponder) Subscribe(msgType string, sub func(sender string, payload []byte)) {}

func (c *testResponder) Get(path string) ([]byte, error) {
	if path != c.path || cts(path, "unknown") {
		return nil, errors.New("not found")
	}

	return c.payload, nil
}

func (c *testResponder) GetHistory(selfID string) ([]json.RawMessage, error) {
	history, ok := c.history[selfID]
	if !ok {
		return nil, errors.New("identity not found")
	}

	return history, nil
}

func (c *testResponder) addpk(selfID string, sk ed25519.PrivateKey, pk ed25519.PublicKey) {
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
