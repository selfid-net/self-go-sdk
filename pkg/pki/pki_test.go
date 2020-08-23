package pki

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPKIGetIndividualHistory(t *testing.T) {
	cfg := Config{
		Transport: newTestPKITransport(
			"/v1/identities/01234567890/history",
			[]byte(`[{"payload": "-", "protected": "-", "signature": "-"}]`),
		),
	}

	c, err := New(cfg)
	require.Nil(t, err)

	history, err := c.GetHistory("01234567890")
	require.Nil(t, err)
	require.Len(t, history, 1)
	assert.True(t, strings.Contains(string(history[0]), "payload"))
	assert.True(t, strings.Contains(string(history[0]), "protected"))
	assert.True(t, strings.Contains(string(history[0]), "signature"))
}

func TestPKIGetAppHistory(t *testing.T) {
	cfg := Config{
		Transport: newTestPKITransport(
			"/v1/apps/long-application-id/history",
			[]byte(`[{"payload": "-", "protected": "-", "signature": "-"}]`),
		),
	}

	c, err := New(cfg)
	require.Nil(t, err)

	history, err := c.GetHistory("long-application-id")
	require.Nil(t, err)
	require.Len(t, history, 1)
	assert.True(t, strings.Contains(string(history[0]), "payload"))
	assert.True(t, strings.Contains(string(history[0]), "protected"))
	assert.True(t, strings.Contains(string(history[0]), "signature"))
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
