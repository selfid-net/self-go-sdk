package pki

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPKIGetIndividualPublicKeys(t *testing.T) {
	cfg := Config{
		Transport: newTestPKITransport(
			"/v1/identities/01234567890/public_keys",
			[]byte(`[{"id":"1", "key":"individual-public-key"}]`),
		),
	}

	c, err := New(cfg)
	require.Nil(t, err)

	keys, err := c.GetPublicKeys("01234567890")
	require.Nil(t, err)
	assert.True(t, strings.Contains(string(keys), "individual-public-key"))
}

func TestPKIGetAppPublicKeys(t *testing.T) {
	cfg := Config{
		Transport: newTestPKITransport(
			"/v1/apps/long-application-id/public_keys",
			[]byte(`[{"id":"1", "key":"app-public-key"}]`),
		),
	}

	c, err := New(cfg)
	require.Nil(t, err)

	keys, err := c.GetPublicKeys("long-application-id")
	require.Nil(t, err)
	assert.True(t, strings.Contains(string(keys), "app-public-key"))
}

func TestPKIGetIndividualDeviceKeys(t *testing.T) {
	cfg := Config{
		Transport: newTestPKITransport(
			"/v1/identities/01234567890/devices/1/pre_keys",
			[]byte(`{"id":"AAAAQ", "key":"individual-pre-key"}`),
		),
	}

	c, err := New(cfg)
	require.Nil(t, err)

	keys, err := c.GetDeviceKey("01234567890", "1")
	require.Nil(t, err)
	assert.True(t, strings.Contains(string(keys), "individual-pre-key"))
}

func TestPKIGetAppDeviceKeys(t *testing.T) {
	cfg := Config{
		Transport: newTestPKITransport(
			"/v1/apps/long-application-id/devices/1/pre_keys",
			[]byte(`{"id":"AAAAQ", "key":"app-pre-key"}`),
		),
	}

	c, err := New(cfg)
	require.Nil(t, err)

	keys, err := c.GetDeviceKey("long-application-id", "1")
	require.Nil(t, err)
	assert.True(t, strings.Contains(string(keys), "app-pre-key"))
}

func TestPKISetIndividualDeviceKeys(t *testing.T) {
	cfg := Config{
		Transport: newTestPKITransport(
			"/v1/identities/01234567890/devices/1/pre_keys",
			nil,
		),
	}

	c, err := New(cfg)
	require.Nil(t, err)

	err = c.SetDeviceKeys("01234567890", "1", []byte(`[{"id":"AAAAQ", "key":"individual-pre-key"}]`))
	require.Nil(t, err)
}

func TestPKISetAppDeviceKeys(t *testing.T) {
	cfg := Config{
		Transport: newTestPKITransport(
			"/v1/apps/long-application-id/devices/1/pre_keys",
			nil,
		),
	}

	c, err := New(cfg)
	require.Nil(t, err)

	err = c.SetDeviceKeys("long-application-id", "1", []byte(`[{"id":"AAAAQ", "key":"app-pre-key"}]`))
	require.Nil(t, err)
}
