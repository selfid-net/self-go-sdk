// Copyright 2020 Self Group Ltd. All Rights Reserved.

package selfsdk

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testWebsocketTransport struct{}

func (t *testWebsocketTransport) Send(recipients []string, data []byte) error {
	return nil
}

func (t *testWebsocketTransport) Receive() (string, []byte, error) {
	time.Sleep(time.Minute)
	return "test:1", []byte("{}"), nil
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

	cfg.SelfAppDeviceSecret = "1:private-key"
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
		SelfAppID:           "self-id",
		DeviceID:            "device-id",
		SelfAppDeviceSecret: "1:" + base64.RawStdEncoding.EncodeToString(sk.Seed()),
		StorageKey:          "super-secret-encryption-key",
		StorageDir:          "/tmp/test",
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
		SelfAppID:           "self-id",
		SelfAppDeviceSecret: "1:" + base64.RawStdEncoding.EncodeToString(sk.Seed()),
		StorageKey:          "super-secret-encryption-key",
		StorageDir:          "/tmp/test",
		Environment:         "sandbox",
		Connectors: &Connectors{
			Rest:      &trt,
			Websocket: &twt,
			Crypto:    &debugCryptoClient{},
		},
	}

	err = cfg.load()
	require.Nil(t, err)

	assert.Equal(t, cfg.APIURL, "https://api.sandbox.joinself.com")
	assert.Equal(t, cfg.MessagingURL, "wss://messaging.sandbox.joinself.com/v1/messaging")
}

func TestConfigStorageMigration(t *testing.T) {
	testPath := filepath.Join("/tmp", uuid.New().String())

	err := os.Mkdir(testPath, 0755)
	require.Nil(t, err)

	defer os.RemoveAll(testPath)

	// create some test files that need to be moved to the new layout
	for _, f := range []string{"test:1.offset", "account.pickle", "app:1-session.pickle", "app:2-session.pickle", "app:3-session.pickle"} {
		_, err = os.Create(filepath.Join(testPath, f))
		require.Nil(t, err)
	}

	cfg := Config{
		SelfAppID:           "self-id",
		SelfAppDeviceSecret: "4:MY-DEVICE-KEY",
		StorageKey:          "super-secret-encryption-key",
		StorageDir:          testPath,
		DeviceID:            "1",
		kid:                 "4",
	}

	err = cfg.migrateStorage()
	require.Nil(t, err)

	// check files have been moved
	_, err = os.Stat(filepath.Join(testPath, "apps/self-id/devices/1/test:1.offset"))
	assert.Nil(t, err)

	_, err = os.Stat(filepath.Join(testPath, "apps/self-id/devices/1/keys/4/account.pickle"))
	assert.Nil(t, err)

	_, err = os.Stat(filepath.Join(testPath, "apps/self-id/devices/1/keys/4/app:1-session.pickle"))
	assert.Nil(t, err)

	_, err = os.Stat(filepath.Join(testPath, "apps/self-id/devices/1/keys/4/app:2-session.pickle"))
	assert.Nil(t, err)

	_, err = os.Stat(filepath.Join(testPath, "apps/self-id/devices/1/keys/4/app:3-session.pickle"))
	assert.Nil(t, err)

	// test second migration
	err = cfg.migrateStorage()
	require.Nil(t, err)
}
