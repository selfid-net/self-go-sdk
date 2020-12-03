// Copyright 2020 Self Group Ltd. All Rights Reserved.

package messaging

import (
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/square/go-jose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

func TestMessagingSubscribe(t *testing.T) {
	_, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	m, p := setup(t)

	cfg := Config{
		SelfID:     "test",
		PrivateKey: ask,
		PKI:        p,
		Messaging:  m,
	}

	p.addpk("sender", sk, pk)

	payload, err := json.Marshal(map[string]string{
		"typ": "test",
		"jti": "12345",
		"cid": "conversation",
		"iss": "sender",
		"aud": "test",
		"sub": "sender",
		"exp": time.Now().Add(time.Minute).Format(time.RFC3339),
		"iat": time.Now().Format(time.RFC3339),
	})

	require.Nil(t, err)

	opts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": "1",
		},
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: sk}, opts)
	require.Nil(t, err)

	req, err := signer.Sign(payload)
	require.Nil(t, err)

	m.sender = "sender:1"
	m.out["test"] = []byte(req.FullSerialize())

	s := NewService(cfg)

	var called bool

	s.Subscribe("test", func(msg *Message) {
		called = true
		assert.Equal(t, "sender:1", msg.Sender)
		assert.Equal(t, "conversation", msg.ConversationID)
		assert.Equal(t, payload, msg.Payload)
	})

	require.True(t, called)
}

func TestMessagingSubscribeEventType(t *testing.T) {
	_, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	m, p := setup(t)

	cfg := Config{
		SelfID:     "test",
		PrivateKey: ask,
		PKI:        p,
		Messaging:  m,
	}

	p.addpk("sender", sk, pk)

	payload, err := json.Marshal(map[string]string{
		"typ": "non-subscribed-type",
		"jti": "12345",
		"cid": "conversation",
		"iss": "sender",
		"aud": "test",
		"sub": "sender",
		"exp": time.Now().Add(time.Minute).Format(time.RFC3339),
		"iat": time.Now().Format(time.RFC3339),
	})

	require.Nil(t, err)

	opts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": "1",
		},
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: sk}, opts)
	require.Nil(t, err)

	req, err := signer.Sign(payload)
	require.Nil(t, err)

	m.sender = "sender:1"
	m.out["non-subscribed-type"] = []byte(req.FullSerialize())

	s := NewService(cfg)

	var called bool

	s.Subscribe("test", func(msg *Message) {
		called = true
	})

	require.False(t, called)
}

func TestMessagingSubscribeBadSignature(t *testing.T) {
	_, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	pk, _, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	m, p := setup(t)

	cfg := Config{
		SelfID:     "test",
		PrivateKey: ask,
		PKI:        p,
		Messaging:  m,
	}

	p.addpk("sender", sk, pk)

	payload, err := json.Marshal(map[string]string{
		"typ": "non-subscribed-type",
		"jti": "12345",
		"cid": "conversation",
		"iss": "sender",
		"aud": "test",
		"sub": "sender",
		"exp": time.Now().Add(time.Minute).Format(time.RFC3339),
		"iat": time.Now().Format(time.RFC3339),
	})

	require.Nil(t, err)

	opts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": "1",
		},
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: sk}, opts)
	require.Nil(t, err)

	req, err := signer.Sign(payload)
	require.Nil(t, err)

	m.sender = "sender:1"
	m.out["test"] = []byte(req.FullSerialize())

	s := NewService(cfg)

	var called bool

	s.Subscribe("test", func(msg *Message) {
		called = true
	})

	require.False(t, called)
}

func TestMessagingSubscribeBadIdentity(t *testing.T) {
	_, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	m, p := setup(t)

	cfg := Config{
		SelfID:     "test",
		PrivateKey: ask,
		PKI:        p,
		Messaging:  m,
	}

	p.addpk("sender", sk, pk)

	payload, err := json.Marshal(map[string]string{
		"typ": "test",
		"jti": "12345",
		"cid": "conversation",
		"iss": "bad-identity",
		"aud": "test",
		"sub": "sender",
		"exp": time.Now().Add(time.Minute).Format(time.RFC3339),
		"iat": time.Now().Format(time.RFC3339),
	})

	require.Nil(t, err)

	opts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": "1",
		},
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: sk}, opts)
	require.Nil(t, err)

	req, err := signer.Sign(payload)
	require.Nil(t, err)

	m.sender = "bad-identity:1"
	m.out["test"] = []byte(req.FullSerialize())

	s := NewService(cfg)

	var called bool

	s.Subscribe("test", func(msg *Message) {
		called = true
	})

	require.False(t, called)
}

func TestMessagingSubscribeExpiredMessage(t *testing.T) {
	_, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	m, p := setup(t)

	cfg := Config{
		SelfID:     "test",
		PrivateKey: ask,
		PKI:        p,
		Messaging:  m,
	}

	p.addpk("sender", sk, pk)

	payload, err := json.Marshal(map[string]string{
		"typ": "test",
		"jti": "12345",
		"cid": "conversation",
		"iss": "sender",
		"aud": "test",
		"sub": "sender",
		"exp": time.Now().Add(-time.Minute).Format(time.RFC3339),
		"iat": time.Now().Add(-time.Hour).Format(time.RFC3339),
	})

	require.Nil(t, err)

	opts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": "1",
		},
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: sk}, opts)
	require.Nil(t, err)

	req, err := signer.Sign(payload)
	require.Nil(t, err)

	m.sender = "sender:1"
	m.out["test"] = []byte(req.FullSerialize())

	s := NewService(cfg)

	var called bool

	s.Subscribe("test", func(msg *Message) {
		called = true
	})

	require.False(t, called)
}

func TestMessagingSubscribeFutureIssued(t *testing.T) {
	_, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	m, p := setup(t)

	cfg := Config{
		SelfID:     "test",
		PrivateKey: ask,
		PKI:        p,
		Messaging:  m,
	}

	p.addpk("sender", sk, pk)

	payload, err := json.Marshal(map[string]string{
		"typ": "test",
		"jti": "12345",
		"cid": "conversation",
		"iss": "sender",
		"aud": "test",
		"sub": "sender",
		"exp": time.Now().Add(time.Minute * 2).Format(time.RFC3339),
		"iat": time.Now().Add(time.Minute).Format(time.RFC3339),
	})

	require.Nil(t, err)

	opts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": "1",
		},
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: sk}, opts)
	require.Nil(t, err)

	req, err := signer.Sign(payload)
	require.Nil(t, err)

	m.sender = "sender:1"
	m.out["test"] = []byte(req.FullSerialize())

	s := NewService(cfg)

	var called bool

	s.Subscribe("test", func(msg *Message) {
		called = true
	})

	require.False(t, called)
}

func TestMessagingRequest(t *testing.T) {
	apk, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	m, p := setup(t)

	cfg := Config{
		SelfID:     "test",
		PrivateKey: ask,
		PKI:        p,
		Messaging:  m,
	}

	m.senderpk = apk
	p.addpk("receiver", sk, pk)

	req, err := json.Marshal(map[string]string{
		"typ": "test",
		"jti": "12345",
		"iss": "test",
		"aud": "receiver",
		"sub": "receiver",
		"exp": time.Now().Add(time.Minute).Format(time.RFC3339),
		"iat": time.Now().Format(time.RFC3339),
	})

	require.Nil(t, err)

	var rpayload []byte
	var called bool

	m.responder = func(r map[string]string) (string, []byte, error) {
		called = true

		assert.NotEmpty(t, r["exp"])
		assert.NotEmpty(t, r["iat"])
		assert.NotEmpty(t, r["jti"])
		assert.NotEmpty(t, r["cid"])
		assert.Equal(t, "test", r["iss"])
		assert.Equal(t, "receiver", r["aud"])
		assert.Equal(t, "receiver", r["sub"])

		rpayload, err = json.Marshal(map[string]string{
			"typ": "test",
			"jti": "12345",
			"cid": r["cid"],
			"iss": "receiver",
			"aud": "test",
			"sub": "test",
			"exp": time.Now().Add(time.Minute).Format(time.RFC3339),
			"iat": time.Now().Format(time.RFC3339),
		})

		require.Nil(t, err)

		opts := &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": "1",
			},
		}

		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: sk}, opts)
		require.Nil(t, err)

		resp, err := signer.Sign(rpayload)
		require.Nil(t, err)

		return "receiver:1", []byte(resp.FullSerialize()), nil
	}

	s := NewService(cfg)

	r, err := s.Request([]string{"receiver:1"}, req)
	require.Nil(t, err)
	require.True(t, called)
	assert.Equal(t, rpayload, r)
}

func TestMessagingRequestTimeout(t *testing.T) {
	apk, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	m, p := setup(t)

	cfg := Config{
		SelfID:     "test",
		PrivateKey: ask,
		PKI:        p,
		Messaging:  m,
	}

	m.senderpk = apk

	req, err := json.Marshal(map[string]string{
		"typ": "test",
		"jti": "12345",
		"iss": "test",
		"aud": "receiver",
		"sub": "receiver",
		"exp": time.Now().Add(time.Minute).Format(time.RFC3339),
		"iat": time.Now().Format(time.RFC3339),
	})

	require.Nil(t, err)

	s := NewService(cfg)

	_, err = s.Request([]string{"receiver:1"}, req)
	require.NotNil(t, err)
}

func TestMessagingRequestBadSignature(t *testing.T) {
	apk, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	pk, _, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	m, p := setup(t)

	cfg := Config{
		SelfID:     "test",
		PrivateKey: ask,
		PKI:        p,
		Messaging:  m,
	}

	m.senderpk = apk
	p.addpk("receiver", sk, pk)

	req, err := json.Marshal(map[string]string{
		"typ": "test",
		"jti": "12345",
		"iss": "test",
		"aud": "receiver",
		"sub": "receiver",
		"exp": time.Now().Add(time.Minute).Format(time.RFC3339),
		"iat": time.Now().Format(time.RFC3339),
	})

	require.Nil(t, err)

	var rpayload []byte
	var called bool

	m.responder = func(r map[string]string) (string, []byte, error) {
		called = true

		assert.NotEmpty(t, r["exp"])
		assert.NotEmpty(t, r["iat"])
		assert.NotEmpty(t, r["jti"])
		assert.NotEmpty(t, r["cid"])
		assert.Equal(t, "test", r["iss"])
		assert.Equal(t, "receiver", r["aud"])
		assert.Equal(t, "receiver", r["sub"])

		rpayload, err = json.Marshal(map[string]string{
			"typ": "test",
			"jti": "12345",
			"cid": r["cid"],
			"iss": "receiver",
			"aud": "test",
			"sub": "test",
			"exp": time.Now().Add(time.Minute).Format(time.RFC3339),
			"iat": time.Now().Format(time.RFC3339),
		})

		require.Nil(t, err)

		opts := &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": "1",
			},
		}

		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: sk}, opts)
		require.Nil(t, err)

		resp, err := signer.Sign(rpayload)
		require.Nil(t, err)

		return "receiver:1", []byte(resp.FullSerialize()), nil
	}

	s := NewService(cfg)

	r, err := s.Request([]string{"receiver:1"}, req)
	require.NotNil(t, err)
	require.True(t, called)
	assert.Nil(t, r)
}

func TestMessagingRequestBadIdentity(t *testing.T) {
	apk, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	m, p := setup(t)

	cfg := Config{
		SelfID:     "test",
		PrivateKey: ask,
		PKI:        p,
		Messaging:  m,
	}

	m.senderpk = apk
	p.addpk("receiver", sk, pk)

	req, err := json.Marshal(map[string]string{
		"typ": "test",
		"jti": "12345",
		"iss": "test",
		"aud": "receiver",
		"sub": "receiver",
		"exp": time.Now().Add(time.Minute).Format(time.RFC3339),
		"iat": time.Now().Format(time.RFC3339),
	})

	require.Nil(t, err)

	var rpayload []byte
	var called bool

	m.responder = func(r map[string]string) (string, []byte, error) {
		called = true

		assert.NotEmpty(t, r["exp"])
		assert.NotEmpty(t, r["iat"])
		assert.NotEmpty(t, r["jti"])
		assert.NotEmpty(t, r["cid"])
		assert.Equal(t, "test", r["iss"])
		assert.Equal(t, "receiver", r["aud"])
		assert.Equal(t, "receiver", r["sub"])

		rpayload, err = json.Marshal(map[string]string{
			"typ": "test",
			"jti": "12345",
			"cid": r["cid"],
			"iss": "bad-identity",
			"aud": "test",
			"sub": "test",
			"exp": time.Now().Add(time.Minute).Format(time.RFC3339),
			"iat": time.Now().Format(time.RFC3339),
		})

		require.Nil(t, err)

		opts := &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": "1",
			},
		}

		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: sk}, opts)
		require.Nil(t, err)

		resp, err := signer.Sign(rpayload)
		require.Nil(t, err)

		return "bad-identity:1", []byte(resp.FullSerialize()), nil
	}

	s := NewService(cfg)

	_, err = s.Request([]string{"receiver:1"}, req)
	require.NotNil(t, err)
	require.True(t, called)
}

func TestMessagingRequestExpiredMessage(t *testing.T) {
	apk, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	m, p := setup(t)

	cfg := Config{
		SelfID:     "test",
		PrivateKey: ask,
		PKI:        p,
		Messaging:  m,
	}

	m.senderpk = apk
	p.addpk("receiver", sk, pk)

	req, err := json.Marshal(map[string]string{
		"typ": "test",
		"jti": "12345",
		"iss": "test",
		"aud": "receiver",
		"sub": "receiver",
		"exp": time.Now().Add(time.Minute).Format(time.RFC3339),
		"iat": time.Now().Format(time.RFC3339),
	})

	require.Nil(t, err)

	var rpayload []byte
	var called bool

	m.responder = func(r map[string]string) (string, []byte, error) {
		called = true

		assert.NotEmpty(t, r["exp"])
		assert.NotEmpty(t, r["iat"])
		assert.NotEmpty(t, r["jti"])
		assert.NotEmpty(t, r["cid"])
		assert.Equal(t, "test", r["iss"])
		assert.Equal(t, "receiver", r["aud"])
		assert.Equal(t, "receiver", r["sub"])

		rpayload, err = json.Marshal(map[string]string{
			"typ": "test",
			"jti": "12345",
			"cid": r["cid"],
			"iss": "receiver",
			"aud": "test",
			"sub": "test",
			"exp": time.Now().Add(-time.Hour).Format(time.RFC3339),
			"iat": time.Now().Add(-time.Hour).Format(time.RFC3339),
		})

		require.Nil(t, err)

		opts := &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": "1",
			},
		}

		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: sk}, opts)
		require.Nil(t, err)

		resp, err := signer.Sign(rpayload)
		require.Nil(t, err)

		return "receiver:1", []byte(resp.FullSerialize()), nil
	}

	s := NewService(cfg)

	_, err = s.Request([]string{"receiver:1"}, req)
	require.NotNil(t, err)
	require.True(t, called)
}

func TestMessagingRequestFutureIssued(t *testing.T) {
	apk, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	m, p := setup(t)

	cfg := Config{
		SelfID:     "test",
		PrivateKey: ask,
		PKI:        p,
		Messaging:  m,
	}

	m.senderpk = apk
	p.addpk("receiver", sk, pk)

	req, err := json.Marshal(map[string]string{
		"typ": "test",
		"jti": "12345",
		"iss": "test",
		"aud": "receiver",
		"sub": "receiver",
		"exp": time.Now().Add(time.Minute).Format(time.RFC3339),
		"iat": time.Now().Format(time.RFC3339),
	})

	require.Nil(t, err)

	var rpayload []byte
	var called bool

	m.responder = func(r map[string]string) (string, []byte, error) {
		called = true

		assert.NotEmpty(t, r["exp"])
		assert.NotEmpty(t, r["iat"])
		assert.NotEmpty(t, r["jti"])
		assert.NotEmpty(t, r["cid"])
		assert.Equal(t, "test", r["iss"])
		assert.Equal(t, "receiver", r["aud"])
		assert.Equal(t, "receiver", r["sub"])

		rpayload, err = json.Marshal(map[string]string{
			"typ": "test",
			"jti": "12345",
			"cid": r["cid"],
			"iss": "receiver",
			"aud": "test",
			"sub": "test",
			"exp": time.Now().Add(time.Hour).Format(time.RFC3339),
			"iat": time.Now().Add(time.Hour).Format(time.RFC3339),
		})

		require.Nil(t, err)

		opts := &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": "1",
			},
		}

		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: sk}, opts)
		require.Nil(t, err)

		resp, err := signer.Sign(rpayload)
		require.Nil(t, err)

		return "receiver:1", []byte(resp.FullSerialize()), nil
	}

	s := NewService(cfg)

	_, err = s.Request([]string{"receiver:1"}, req)
	require.NotNil(t, err)
	require.True(t, called)
}

func TestMessagingRespond(t *testing.T) {
	apk, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	m, p := setup(t)

	cfg := Config{
		SelfID:     "test",
		PrivateKey: ask,
		PKI:        p,
		Messaging:  m,
	}

	payload, err := json.Marshal(map[string]string{
		"typ": "test",
		"jti": "12345",
		"iss": "sender",
		"aud": "test",
		"sub": "sender",
		"exp": time.Now().Add(time.Minute).Format(time.RFC3339),
		"iat": time.Now().Format(time.RFC3339),
	})

	require.Nil(t, err)

	s := NewService(cfg)

	err = s.Respond("sender:1", "conversation", payload)
	require.Nil(t, err)

	jws, err := jose.ParseSigned(string(m.in))
	require.Nil(t, err)

	rp, err := jws.Verify(apk)
	require.Nil(t, err)

	var r map[string]string

	err = json.Unmarshal(rp, &r)
	require.Nil(t, err)

	assert.Equal(t, "conversation", r["cid"])
	assert.Equal(t, "sender", r["iss"])
	assert.Equal(t, "test", r["aud"])
}
