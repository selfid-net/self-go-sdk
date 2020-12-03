// Copyright 2020 Self Group Ltd. All Rights Reserved.

package messaging

import (
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/square/go-jose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

func TestMessagingPermitConnection(t *testing.T) {
	apk, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	m, p := setup(t)

	cfg := Config{
		SelfID:     "test",
		PrivateKey: ask,
		PKI:        p,
		Messaging:  m,
	}

	s := NewService(cfg)

	err = s.PermitConnection("app")
	require.Nil(t, err)
	assert.NotNil(t, m.out["acl.permit"])

	jws, err := jose.ParseSigned(string(m.out["acl.permit"]))
	require.Nil(t, err)

	payload, err := jws.Verify(apk)
	require.Nil(t, err)

	var cmd map[string]string

	err = json.Unmarshal(payload, &cmd)
	require.Nil(t, err)

	assert.NotEmpty(t, cmd["exp"])
	assert.NotEmpty(t, cmd["iat"])
	assert.NotEmpty(t, cmd["jti"])
	assert.Equal(t, "test", cmd["iss"])
	assert.Equal(t, "app", cmd["acl_source"])
}

func TestMessagingRevokeConnection(t *testing.T) {
	apk, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	m, p := setup(t)

	cfg := Config{
		SelfID:     "test",
		PrivateKey: ask,
		PKI:        p,
		Messaging:  m,
	}

	s := NewService(cfg)

	err = s.RevokeConnection("app")
	require.Nil(t, err)
	assert.NotNil(t, m.out["acl.revoke"])

	jws, err := jose.ParseSigned(string(m.out["acl.revoke"]))
	require.Nil(t, err)

	payload, err := jws.Verify(apk)
	require.Nil(t, err)

	var cmd map[string]string

	err = json.Unmarshal(payload, &cmd)
	require.Nil(t, err)

	assert.NotEmpty(t, cmd["exp"])
	assert.NotEmpty(t, cmd["iat"])
	assert.NotEmpty(t, cmd["jti"])
	assert.Equal(t, "test", cmd["iss"])
	assert.Equal(t, "app", cmd["acl_source"])
}

func TestMessagingListConnections(t *testing.T) {
	_, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	m, p := setup(t)

	cfg := Config{
		SelfID:     "test",
		PrivateKey: ask,
		PKI:        p,
		Messaging:  m,
	}

	s := NewService(cfg)

	m.in, err = json.Marshal([]string{
		"app-1",
		"app-2",
		"app-3",
	})

	permitted, err := s.ListConnections()
	require.Nil(t, err)
	assert.Nil(t, m.out["acl.list"])

	assert.Equal(t, []string{"app-1", "app-2", "app-3"}, permitted)
}
