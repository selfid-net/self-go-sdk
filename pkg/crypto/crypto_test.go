package crypto

import (
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/selfid-net/self-crypto-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

func TestCryptoClientPublishDeviceKeys(t *testing.T) {
	_, pki, storage := setup(t, 1)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	cfg := Config{
		SelfID:     "test",
		DeviceID:   "1",
		PrivateKey: sk,
		StorageKey: "my-secret-key",
		Storage:    storage,
		PKI:        pki,
	}

	_, err = New(cfg)
	require.Nil(t, err)

	assert.NotNil(t, pki.dkeys["test:1"])
}

func TestCryptoClientEncrypt(t *testing.T) {
	rcps, pki, storage := setup(t, 1)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	cfg := Config{
		SelfID:     "test",
		DeviceID:   "1",
		PrivateKey: sk,
		StorageKey: "my-secret-key",
		Storage:    storage,
		PKI:        pki,
	}

	c, err := New(cfg)
	require.Nil(t, err)

	recips := recipients(rcps)

	ciphertext, err := c.Encrypt(recips, []byte("hello"))
	require.Nil(t, err)

	var gm selfcrypto.GroupMessage

	err = json.Unmarshal(ciphertext, &gm)
	require.Nil(t, err)

	require.Len(t, gm.Recipients, 1)
	assert.NotNil(t, gm.Recipients[recips[0]])
	assert.NotEqual(t, []byte("hello"), gm.Ciphertext)

	recip := rcps[recips[0]]

	gs := recip.createInboundGroupSesson(t, "test:1", &gm)

	plaintext, err := gs.Decrypt("test:1", ciphertext)
	require.Nil(t, err)
	assert.Equal(t, []byte("hello"), plaintext)
}

func TestCryptoClientEncryptMultipleRecipients(t *testing.T) {
	rcps, pki, storage := setup(t, 20)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	cfg := Config{
		SelfID:     "test",
		DeviceID:   "1",
		PrivateKey: sk,
		StorageKey: "my-secret-key",
		Storage:    storage,
		PKI:        pki,
	}

	c, err := New(cfg)
	require.Nil(t, err)

	recips := recipients(rcps)

	ciphertext, err := c.Encrypt(recips, []byte("hello"))
	require.Nil(t, err)

	var gm selfcrypto.GroupMessage

	err = json.Unmarshal(ciphertext, &gm)
	require.Nil(t, err)

	require.Len(t, gm.Recipients, 20)
	assert.NotEqual(t, []byte("hello"), gm.Ciphertext)

	for _, recip := range recips {
		assert.NotNil(t, gm.Recipients[recip])
		gs := rcps[recip].createInboundGroupSesson(t, "test:1", &gm)

		plaintext, err := gs.Decrypt("test:1", ciphertext)
		require.Nil(t, err)
		assert.Equal(t, []byte("hello"), plaintext)
	}
}

func TestCryptoClientEncryptExistingRecipient(t *testing.T) {
	rcps, pki, storage := setup(t, 20)

	_, sk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	cfg := Config{
		SelfID:     "test",
		DeviceID:   "1",
		PrivateKey: sk,
		StorageKey: "my-secret-key",
		Storage:    storage,
		PKI:        pki,
	}

	c, err := New(cfg)
	require.Nil(t, err)

	recips := recipients(rcps)

	// establish session with new recipient
	idks, err := c.account.IdentityKeys()
	require.Nil(t, err)

	otks, err := c.account.OneTimeKeys()
	require.Nil(t, err)

	ct := rcps[recips[0]].encryptNewMessage(
		t,
		"test:1",
		[]byte("ehlo"),
		idks.Curve25519,
		otks.Curve25519["AAAAAQ"],
	)

	ps, err := selfcrypto.CreateInboundSession(c.account, recips[0], ct)
	require.Nil(t, err)

	pt, err := ps.Decrypt(ct)
	require.Nil(t, err)
	assert.Equal(t, []byte("ehlo"), pt)

	// encrypt a group message
	ciphertext, err := c.Encrypt(recips, []byte("hello"))
	require.Nil(t, err)

	var gm selfcrypto.GroupMessage

	err = json.Unmarshal(ciphertext, &gm)
	require.Nil(t, err)

	require.Len(t, gm.Recipients, 20)
	assert.NotEqual(t, []byte("hello"), gm.Ciphertext)

	for _, recip := range recips {
		assert.NotNil(t, gm.Recipients[recip])
		gs := rcps[recip].createInboundGroupSesson(t, "test:1", &gm)

		plaintext, err := gs.Decrypt("test:1", ciphertext)
		require.Nil(t, err)
		assert.Equal(t, []byte("hello"), plaintext)
	}
}

func TestCryptoClientDecrypt(t *testing.T) {
	_, pki, astorage := setup(t, 1)
	_, _, bstorage := setup(t, 1)

	// setup alice
	_, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	acfg := Config{
		SelfID:     "alice",
		DeviceID:   "1",
		PrivateKey: ask,
		StorageKey: "my-secret-key",
		Storage:    astorage,
		PKI:        pki,
	}

	ac, err := New(acfg)
	require.Nil(t, err)

	// setup bob
	_, bsk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	bcfg := Config{
		SelfID:     "bob",
		DeviceID:   "1",
		PrivateKey: bsk,
		StorageKey: "my-secret-key",
		Storage:    bstorage,
		PKI:        pki,
	}

	bc, err := New(bcfg)
	require.Nil(t, err)

	// publish alices public key
	idks, err := ac.account.IdentityKeys()
	require.Nil(t, err)
	pki.pkeys["alice"] = []byte(`[{"id": 0, "key": "` + idks.Ed25519 + `"}]`)

	// publish bobs public key
	idks, err = bc.account.IdentityKeys()
	require.Nil(t, err)
	pki.pkeys["bob"] = []byte(`[{"id": 0, "key": "` + idks.Ed25519 + `"}]`)

	// encrypt from alices session
	ciphertext, err := ac.Encrypt([]string{"bob:1"}, []byte("hello"))
	require.Nil(t, err)

	// descrypt from bobs session
	plaintext, err := bc.Decrypt("alice:1", ciphertext)
	require.Nil(t, err)
	assert.Equal(t, []byte("hello"), plaintext)
}

func TestCryptoClientExhaustPreKeys(t *testing.T) {
	senders, pki, astorage := setup(t, 101)

	// setup alice
	_, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	acfg := Config{
		SelfID:     "alice",
		DeviceID:   "1",
		PrivateKey: ask,
		StorageKey: "my-secret-key",
		Storage:    astorage,
		PKI:        pki,
	}

	ac, err := New(acfg)
	require.Nil(t, err)

	// publish alices public key
	idks, err := ac.account.IdentityKeys()
	require.Nil(t, err)
	pki.pkeys["alice"] = []byte(`[{"id": 0, "key": "` + idks.Ed25519 + `"}]`)

	for _, sender := range senders {
		// setup bob
		_, bsk, err := ed25519.GenerateKey(rand.Reader)
		require.Nil(t, err)

		bcfg := Config{
			SelfID:     sender.selfID(),
			DeviceID:   "1",
			PrivateKey: bsk,
			StorageKey: "my-secret-key",
			Storage:    newTestStorage(t),
			PKI:        pki,
		}

		bc, err := New(bcfg)
		require.Nil(t, err)

		// publish bobs public key
		idks, err := bc.account.IdentityKeys()
		require.Nil(t, err)
		pki.pkeys[sender.selfID()] = []byte(`[{"id": 0, "key": "` + idks.Ed25519 + `"}]`)

		// encrypt from senders session
		ciphertext, err := bc.Encrypt([]string{"alice:1"}, []byte("hello"))
		require.Nil(t, err)

		// decrypt from alices session
		plaintext, err := ac.Decrypt(sender.id, ciphertext)
		require.Nil(t, err)
		assert.Equal(t, []byte("hello"), plaintext)
	}
}
