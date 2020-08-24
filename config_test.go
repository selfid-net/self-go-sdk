package selfsdk

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testWebsocketTransport struct{}

func (t *testWebsocketTransport) Send(recipients []string, data []byte) error {
	return nil
}

func (t *testWebsocketTransport) Receive() (string, []byte, error) {
	return "", nil, nil
}

func (t *testWebsocketTransport) Command(command string, payload []byte) ([]byte, error) {
	return nil, nil
}

func (t *testWebsocketTransport) Close() error {
	return nil
}

type testRestTransport struct{}

func (t *testRestTransport) Get(path string) ([]byte, error) {
	return nil, nil
}

func (t *testRestTransport) Post(path string, ctype string, data []byte) ([]byte, error) {
	return nil, nil
}

func (t *testRestTransport) Put(path string, ctype string, data []byte) ([]byte, error) {
	return nil, nil
}

func (t *testRestTransport) Delete(path string) ([]byte, error) {
	return nil, nil
}

func TestConfigValidate(t *testing.T) {
	cfg := Config{}

	err := cfg.validate()
	assert.NotNil(t, err)

	cfg.SelfAppID = "self-id"
	err = cfg.validate()
	assert.NotNil(t, err)

	cfg.DeviceID = "device-id"
	err = cfg.validate()
	assert.NotNil(t, err)

	cfg.SelfAppSecret = "private-key"
	err = cfg.validate()
	assert.NotNil(t, err)

	cfg.StorageDir = "/tmp/test"
	err = cfg.validate()
	assert.NotNil(t, err)

	cfg.StorageKey = "super-secret-encryption-key"
	err = cfg.validate()
	assert.Nil(t, err)
}

func TestConfigLoad(t *testing.T) {
	var twt testWebsocketTransport
	var trt testRestTransport

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	cfg := Config{
		SelfAppID:     "self-id",
		DeviceID:      "device-id",
		SelfAppSecret: base64.RawStdEncoding.EncodeToString(sk.Seed()),
		StorageKey:    "super-secret-encryption-key",
		StorageDir:    "/tmp/test",
		Connectors: &Connectors{
			Rest:      &trt,
			Websocket: &twt,
		},
	}

	err = cfg.load()
	require.Nil(t, err)

	assert.Equal(t, &trt, cfg.Connectors.Rest)
	assert.Equal(t, &twt, cfg.Connectors.Websocket)
	assert.NotNil(t, cfg.Connectors.PKI)
	assert.NotNil(t, cfg.Connectors.Crypto)
	assert.NotNil(t, cfg.Connectors.Storage)
	assert.NotNil(t, cfg.Connectors.Messaging)
	assert.Equal(t, cfg.APIURL, "https://api.joinself.com")
	assert.Equal(t, cfg.MessagingURL, "wss://messaging.joinself.com/v1/messaging")
}

func TestConfigLoadWithEnvironment(t *testing.T) {
	var twt testWebsocketTransport
	var trt testRestTransport

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	cfg := Config{
		SelfAppID:     "self-id",
		SelfAppSecret: base64.RawStdEncoding.EncodeToString(sk.Seed()),
		StorageKey:    "super-secret-encryption-key",
		Environment:   "sandbox",
		Connectors: &Connectors{
			Rest:      &trt,
			Websocket: &twt,
		},
	}

	err = cfg.load()
	require.Nil(t, err)

	assert.Equal(t, cfg.APIURL, "https://api.sandbox.joinself.com")
	assert.Equal(t, cfg.MessagingURL, "wss://messaging.sandbox.joinself.com/v1/messaging")
}
