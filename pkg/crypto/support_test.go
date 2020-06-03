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

	"github.com/selfid-net/self-crypto-go"
	"github.com/google/uuid"
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

		// store the identities public key
		pks := pubkeys{
			{
				ID:  0,
				Key: base64.RawStdEncoding.EncodeToString(pk),
			},
		}

		pki.pkeys[id], err = json.Marshal(pks)
		require.Nil(t, err)

		rcp[id+":1"] = recipient{id: id + ":1", account: a, pk: pk, sk: sk}
	}

	return rcp, pki, newTestStorage(t)
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
	dkoff map[string]int
	dkeys map[string][]byte
	pkeys map[string][]byte
}

func newTestPKI(t *testing.T) *testPKI {
	return &testPKI{
		dkoff: make(map[string]int),
		dkeys: make(map[string][]byte),
		pkeys: make(map[string][]byte),
	}
}

func (p *testPKI) GetPublicKeys(selfID string) ([]byte, error) {
	return p.pkeys[selfID], nil
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
