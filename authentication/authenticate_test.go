package authentication

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/square/go-jose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

func TestAuthenticationRequest(t *testing.T) {
	tr, cfg := setup(t)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	var called bool

	tr.responder = func(req map[string]string) (string, []byte, error) {
		called = true

		assert.NotEmpty(t, req["jti"])
		assert.NotEmpty(t, req["cid"])
		assert.NotEmpty(t, req["exp"])
		assert.NotEmpty(t, req["iat"])
		assert.Equal(t, "identities.authenticate.req", req["typ"])
		assert.Equal(t, cfg.SelfID, req["iss"])
		assert.Equal(t, "1234567890", req["aud"])
		assert.Equal(t, cfg.DeviceID, req["device_id"])

		resp, err := json.Marshal(map[string]string{
			"jti":    uuid.New().String(),
			"cid":    req["cid"],
			"typ":    "identities.authenticate.resp",
			"iss":    req["sub"],
			"sub":    req["sub"],
			"aud":    req["iss"],
			"iat":    time.Now().Format(time.RFC3339),
			"exp":    time.Now().Add(time.Minute).Format(time.RFC3339),
			"status": "accepted",
		})

		require.Nil(t, err)

		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: sk}, nil)
		require.Nil(t, err)

		jws, err := s.Sign(resp)

		return req["sub"], []byte(jws.FullSerialize()), err
	}

	tr.addpk("1234567890", pk)
	tr.path = "/v1/identities/1234567890/devices"
	tr.payload = []byte(`["1", "2"]`)

	c := NewService(cfg)

	err = c.Request("1234567890")
	require.Nil(t, err)
	assert.True(t, called)
}

func TestAuthenticationRequestTimeout(t *testing.T) {
	tr, cfg := setup(t)

	pk, _, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	var called bool

	tr.responder = func(req map[string]string) (string, []byte, error) {
		called = true
		return "", nil, errors.New("request timeout")
	}

	tr.addpk("1234567890", pk)
	tr.path = "/v1/identities/1234567890/devices"
	tr.payload = []byte(`["1", "2"]`)

	c := NewService(cfg)
	c.expiry = time.Millisecond

	err = c.Request("1234567890")
	require.NotNil(t, err)
	assert.True(t, called)
}

func TestAuthenticationBadSignature(t *testing.T) {
	tr, cfg := setup(t)

	// generate a different public key for the responder
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	pk, _, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	var called bool

	tr.responder = func(req map[string]string) (string, []byte, error) {
		called = true

		assert.NotEmpty(t, req["jti"])
		assert.NotEmpty(t, req["cid"])
		assert.NotEmpty(t, req["exp"])
		assert.NotEmpty(t, req["iat"])
		assert.Equal(t, "identities.authenticate.req", req["typ"])
		assert.Equal(t, cfg.SelfID, req["iss"])
		assert.Equal(t, "1234567890", req["aud"])
		assert.Equal(t, cfg.DeviceID, req["device_id"])

		resp, err := json.Marshal(map[string]string{
			"jti":    uuid.New().String(),
			"cid":    req["cid"],
			"typ":    "identities.authenticate.resp",
			"iss":    req["sub"],
			"sub":    req["sub"],
			"aud":    req["iss"],
			"iat":    time.Now().Format(time.RFC3339),
			"exp":    time.Now().Add(time.Minute).Format(time.RFC3339),
			"status": "accepted",
		})

		require.Nil(t, err)

		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: sk}, nil)
		require.Nil(t, err)

		jws, err := s.Sign(resp)

		return req["sub"], []byte(jws.FullSerialize()), err
	}

	tr.addpk("1234567890", pk)
	tr.path = "/v1/identities/1234567890/devices"
	tr.payload = []byte(`["1", "2"]`)

	c := NewService(cfg)

	err = c.Request("1234567890")
	require.NotNil(t, err)
	assert.True(t, called)
}

func TestAuthenticationBadIssuingIdentity(t *testing.T) {
	tr, cfg := setup(t)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	var called bool

	tr.responder = func(req map[string]string) (string, []byte, error) {
		called = true

		assert.NotEmpty(t, req["jti"])
		assert.NotEmpty(t, req["cid"])
		assert.NotEmpty(t, req["exp"])
		assert.NotEmpty(t, req["iat"])
		assert.Equal(t, "identities.authenticate.req", req["typ"])
		assert.Equal(t, cfg.SelfID, req["iss"])
		assert.Equal(t, "1234567890", req["aud"])
		assert.Equal(t, cfg.DeviceID, req["device_id"])

		resp, err := json.Marshal(map[string]string{
			"jti":    uuid.New().String(),
			"cid":    req["cid"],
			"typ":    "identities.authenticate.resp",
			"iss":    "some-other-individual",
			"sub":    req["sub"],
			"aud":    req["iss"],
			"iat":    time.Now().Format(time.RFC3339),
			"exp":    time.Now().Add(time.Minute).Format(time.RFC3339),
			"status": "accepted",
		})

		require.Nil(t, err)

		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: sk}, nil)
		require.Nil(t, err)

		jws, err := s.Sign(resp)

		return "some-other-individual", []byte(jws.FullSerialize()), err
	}

	tr.addpk("1234567890", pk)
	tr.path = "/v1/identities/1234567890/devices"
	tr.payload = []byte(`["1", "2"]`)

	c := NewService(cfg)

	err = c.Request("1234567890")
	require.NotNil(t, err)
	assert.True(t, called)
}

func TestAuthenticationBadAudienceIdentity(t *testing.T) {
	tr, cfg := setup(t)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	var called bool

	tr.responder = func(req map[string]string) (string, []byte, error) {
		called = true

		assert.NotEmpty(t, req["jti"])
		assert.NotEmpty(t, req["cid"])
		assert.NotEmpty(t, req["exp"])
		assert.NotEmpty(t, req["iat"])
		assert.Equal(t, "identities.authenticate.req", req["typ"])
		assert.Equal(t, cfg.SelfID, req["iss"])
		assert.Equal(t, "1234567890", req["aud"])
		assert.Equal(t, cfg.DeviceID, req["device_id"])

		resp, err := json.Marshal(map[string]string{
			"jti":    uuid.New().String(),
			"cid":    req["cid"],
			"typ":    "identities.authenticate.resp",
			"iss":    req["sub"],
			"sub":    req["sub"],
			"aud":    "some-other-app",
			"iat":    time.Now().Format(time.RFC3339),
			"exp":    time.Now().Add(time.Minute).Format(time.RFC3339),
			"status": "accepted",
		})

		require.Nil(t, err)

		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: sk}, nil)
		require.Nil(t, err)

		jws, err := s.Sign(resp)

		return req["sub"], []byte(jws.FullSerialize()), err
	}

	tr.addpk("1234567890", pk)
	tr.path = "/v1/identities/1234567890/devices"
	tr.payload = []byte(`["1", "2"]`)

	c := NewService(cfg)

	err = c.Request("1234567890")
	require.NotNil(t, err)
	assert.True(t, called)
}

func TestAuthenticationRequestExpired(t *testing.T) {
	tr, cfg := setup(t)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	var called bool

	tr.responder = func(req map[string]string) (string, []byte, error) {
		called = true

		assert.NotEmpty(t, req["jti"])
		assert.NotEmpty(t, req["cid"])
		assert.NotEmpty(t, req["exp"])
		assert.NotEmpty(t, req["iat"])
		assert.Equal(t, "identities.authenticate.req", req["typ"])
		assert.Equal(t, cfg.SelfID, req["iss"])
		assert.Equal(t, "1234567890", req["aud"])
		assert.Equal(t, cfg.DeviceID, req["device_id"])

		resp, err := json.Marshal(map[string]string{
			"jti":    uuid.New().String(),
			"cid":    req["cid"],
			"typ":    "identities.authenticate.resp",
			"iss":    req["sub"],
			"sub":    req["sub"],
			"aud":    req["iss"],
			"iat":    time.Now().Add(-time.Hour).Format(time.RFC3339),
			"exp":    time.Now().Add(-time.Minute).Format(time.RFC3339),
			"status": "accepted",
		})

		require.Nil(t, err)

		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: sk}, nil)
		require.Nil(t, err)

		jws, err := s.Sign(resp)

		return req["sub"], []byte(jws.FullSerialize()), err
	}

	tr.addpk("1234567890", pk)
	tr.path = "/v1/identities/1234567890/devices"
	tr.payload = []byte(`["1", "2"]`)

	c := NewService(cfg)

	err = c.Request("1234567890")
	require.NotNil(t, err)
	assert.True(t, called)
}

func TestAuthenticationRequestIssuedInFuture(t *testing.T) {
	tr, cfg := setup(t)

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	var called bool

	tr.responder = func(req map[string]string) (string, []byte, error) {
		called = true

		assert.NotEmpty(t, req["jti"])
		assert.NotEmpty(t, req["cid"])
		assert.NotEmpty(t, req["exp"])
		assert.NotEmpty(t, req["iat"])
		assert.Equal(t, "identities.authenticate.req", req["typ"])
		assert.Equal(t, cfg.SelfID, req["iss"])
		assert.Equal(t, "1234567890", req["aud"])
		assert.Equal(t, cfg.DeviceID, req["device_id"])

		resp, err := json.Marshal(map[string]string{
			"jti":    uuid.New().String(),
			"cid":    req["cid"],
			"typ":    "identities.authenticate.resp",
			"iss":    req["sub"],
			"sub":    req["sub"],
			"aud":    req["iss"],
			"iat":    time.Now().Add(time.Minute).Format(time.RFC3339),
			"exp":    time.Now().Add(time.Minute * 5).Format(time.RFC3339),
			"status": "accepted",
		})

		require.Nil(t, err)

		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: sk}, nil)
		require.Nil(t, err)

		jws, err := s.Sign(resp)

		return req["sub"], []byte(jws.FullSerialize()), err
	}

	tr.addpk("1234567890", pk)
	tr.path = "/v1/identities/1234567890/devices"
	tr.payload = []byte(`["1", "2"]`)

	c := NewService(cfg)

	err = c.Request("1234567890")
	require.NotNil(t, err)
	assert.True(t, called)
}
