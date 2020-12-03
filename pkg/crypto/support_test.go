// Copyright 2020 Self Group Ltd. All Rights Reserved.

package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	mrand "math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	selfcrypto "github.com/joinself/self-crypto-go"
	"github.com/joinself/self-go-sdk/pkg/siggraph"
	"github.com/square/go-jose"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

func setup(t *testing.T, recipients int) (map[string]recipient, *testPKI, *testStorage) {
	pki := newTestPKI(t)
	rcp := make(map[string]recipient)

	for i := 0; i < recipients; i++ {
		// generate a recipient id
		id := uuid.New().String()

		// generate an identity keypair
		pk, sk, err := ed25519.GenerateKey(rand.Reader)
		require.Nil(t, err)

		// create an selfcrypto account from the private key
		a, err := selfcrypto.AccountFromSeed(id+":1", sk.Seed())
		require.Nil(t, err)

		// generate and store the accounts one time keys
		err = a.GenerateOneTimeKeys(10)
		require.Nil(t, err)

		otks, err := a.OneTimeKeys()
		require.Nil(t, err)

		var pkb prekeys

		for k, v := range otks.Curve25519 {
			pkb = append(pkb, prekey{ID: k, Key: v})
		}

		pkbd, err := json.Marshal(pkb)
		require.Nil(t, err)

		pki.SetDeviceKeys(id, "1", pkbd)

		a.MarkKeysAsPublished()

		pki.addpk(id, sk, pk)

		rcp[id+":1"] = recipient{id: id + ":1", account: a, pk: pk, sk: sk}
	}

	return rcp, pki, newTestStorage(t)
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

func recipients(r map[string]recipient) []string {
	arcp := make([]string, 0, len(r))

	for k := range r {
		arcp = append(arcp, k)
	}

	return arcp
}

func randomRecipients(r map[string]recipient, max int) []string {
	arcp := make([]string, 0, len(r))
	rcp := make([]string, 0, max)

	for k := range r {
		arcp = append(arcp, k)
	}

	for i := 0; i < max; i++ {
		rnd := mrand.Intn(len(arcp))
		rcp = append(rcp, arcp[rnd])
	}

	return rcp
}

type recipient struct {
	id      string
	account *selfcrypto.Account
	session *selfcrypto.Session
	pk      ed25519.PublicKey
	sk      ed25519.PrivateKey
}

func (r recipient) createInboundGroupSesson(t *testing.T, from string, gm *selfcrypto.GroupMessage) *selfcrypto.GroupSession {
	cas, err := selfcrypto.CreateInboundSession(r.account, from, gm.Recipients[r.id])
	require.Nil(t, err)

	gs, err := selfcrypto.CreateGroupSession(r.account, []*selfcrypto.Session{cas})
	require.Nil(t, err)

	return gs
}

func (r recipient) encryptNewMessage(t *testing.T, recipient string, pt []byte, ik, otk string) *selfcrypto.Message {
	s, err := selfcrypto.CreateOutboundSession(r.account, recipient, ik, otk)
	require.Nil(t, err)

	ct, err := s.Encrypt(pt)
	require.Nil(t, err)

	return ct
}

func (r recipient) selfID() string {
	return strings.Split(r.id, ":")[0]
}

func createTestDirectory(t *testing.T) string {
	sdir := filepath.Join("/tmp", uuid.New().String())

	err := os.MkdirAll(sdir, 0744)
	require.Nil(t, err)

	return sdir
}

type testPKI struct {
	dkoff   map[string]int
	dkeys   map[string][]byte
	history map[string][]json.RawMessage
}

func newTestPKI(t *testing.T) *testPKI {
	return &testPKI{
		dkoff:   make(map[string]int),
		dkeys:   make(map[string][]byte),
		history: make(map[string][]json.RawMessage),
	}
}

func (p *testPKI) GetHistory(selfID string) ([]json.RawMessage, error) {
	return p.history[selfID], nil
}

func (p *testPKI) GetDeviceKey(selfID, deviceID string) ([]byte, error) {
	var keys prekeys

	err := json.Unmarshal(p.dkeys[selfID+":"+deviceID], &keys)
	if err != nil {
		return nil, err
	}

	kid := p.dkoff[selfID+":"+deviceID]

	if kid > len(keys) {
		return nil, errors.New("prekeys exhausted")
	}

	p.dkoff[selfID+":"+deviceID]++

	return json.Marshal(keys[kid])
}

func (p *testPKI) SetDeviceKeys(selfID, deviceID string, pkb []byte) error {
	p.dkeys[selfID+":"+deviceID] = pkb
	return nil
}

func (p *testPKI) addpk(selfID string, sk ed25519.PrivateKey, pk ed25519.PublicKey) {
	now := time.Now().Unix()

	rpk, _, _ := ed25519.GenerateKey(rand.Reader)

	p.history[selfID] = []json.RawMessage{
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

type testStorage struct {
	account  []byte
	sessions map[string][]byte
}

func newTestStorage(t *testing.T) *testStorage {
	return &testStorage{
		sessions: make(map[string][]byte),
	}
}

func (s *testStorage) GetAccount() ([]byte, error) {
	return s.account, nil
}

func (s *testStorage) SetAccount(account []byte) error {
	s.account = account
	return nil
}

func (s *testStorage) GetSession(id string) ([]byte, error) {
	return s.sessions[id], nil
}

func (s *testStorage) SetSession(id string, session []byte) error {
	s.sessions[id] = session
	return nil
}
