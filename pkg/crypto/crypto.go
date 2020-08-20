package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"

	selfcrypto "github.com/joinself/self-crypto-go"
	"github.com/joinself/self-go-sdk/pkg/pki"
	"golang.org/x/crypto/ed25519"
)

var defaultPreKeyBundleSize = 100

type prekeys []prekey

type pubkeys []pubkey

type prekey struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

type pubkey struct {
	ID  int    `json:"id"`
	Key string `json:"key"`
}

// PKI the public key infrastructure provider used to retrieve and store keys
type PKI interface {
	GetPublicKeys(selfID string) ([]byte, error)
	GetDeviceKey(selfID, deviceID string) ([]byte, error)
	SetDeviceKeys(selfID, deviceID string, pkb []byte) error
}

// Storage the stateful provider used to retreive crypto sessions and account
type Storage interface {
	GetAccount() ([]byte, error)
	SetAccount(account []byte) error
	GetSession(recipient string) ([]byte, error)
	SetSession(recipient string, session []byte) error
}

// Config crypto configuration for managing e2e encrypted sessions
type Config struct {
	SelfID           string
	DeviceID         string
	PrivateKey       ed25519.PrivateKey
	PreKeyBundleSize int
	StorageDir       string
	StorageKey       string
	APIURL           string
	PKI              PKI
	Storage          Storage
}

// Client default implementation of a messaging client
type Client struct {
	config  Config
	address string
	pki     PKI
	storage Storage
	account *selfcrypto.Account
	mu      sync.Mutex
}

// New creates a new crypto client for encrypting and decrypting messages
func New(config Config) (*Client, error) {
	if config.PKI == nil {
		cfg := pki.Config{
			SelfID:     config.SelfID,
			PrivateKey: config.PrivateKey,
			APIURL:     config.APIURL,
		}

		pki, err := pki.New(cfg)
		if err != nil {
			return nil, err
		}

		config.PKI = pki
	}

	if config.Storage == nil {
		cfg := StorageConfig{
			StorageDir: config.StorageDir,
		}

		sm, err := NewFileStorage(cfg)
		if err != nil {
			return nil, err
		}

		config.Storage = sm
	}

	if config.PreKeyBundleSize == 0 {
		config.PreKeyBundleSize = defaultPreKeyBundleSize
	}

	c := &Client{
		config:  config,
		pki:     config.PKI,
		storage: config.Storage,
		address: fmt.Sprintf(
			"%s:%s",
			config.SelfID,
			config.DeviceID,
		),
	}

	ap, err := c.storage.GetAccount()
	if err != nil {
		return nil, err
	}

	if ap == nil {
		c.account, err = c.createAccount()
	} else {
		c.account, err = selfcrypto.AccountFromPickle(c.address, c.config.StorageKey, string(ap))
	}

	return c, err
}

// Encrypt encrypt a message for any number of recipients
func (c *Client) Encrypt(recipients []string, plaintext []byte) ([]byte, error) {
	sessions := make([]*selfcrypto.Session, len(recipients))

	c.mu.Lock()
	defer c.mu.Unlock()

	for i, r := range recipients {
		var s *selfcrypto.Session

		sp, err := c.storage.GetSession(r)
		if err != nil {
			return nil, err
		}

		if sp == nil {
			s, err = c.createOutboundSession(r)
		} else {
			s, err = selfcrypto.SessionFromPickle(r, c.config.StorageKey, string(sp))
		}

		if err != nil {
			return nil, err
		}

		sessions[i] = s
	}

	gs, err := selfcrypto.CreateGroupSession(c.account, sessions)
	if err != nil {
		return nil, err
	}

	ciphertext, err := gs.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}

	for i, s := range sessions {
		sp, err := s.Pickle(c.config.StorageKey)
		if err != nil {
			return nil, err
		}

		err = c.storage.SetSession(recipients[i], []byte(sp))
		if err != nil {
			return nil, err
		}
	}

	return ciphertext, nil
}

// Decrypt decrypt a message from a recipient
func (c *Client) Decrypt(sender string, ciphertext []byte) ([]byte, error) {
	var s *selfcrypto.Session

	c.mu.Lock()
	defer c.mu.Unlock()

	sp, err := c.storage.GetSession(sender)
	if err != nil {
		return nil, err
	}

	if sp == nil {
		s, err = c.createInboundSession(sender, ciphertext)
	} else {
		s, err = selfcrypto.SessionFromPickle(sender, c.config.StorageKey, string(sp))
	}

	if err != nil {
		return nil, err
	}

	gs, err := selfcrypto.CreateGroupSession(c.account, []*selfcrypto.Session{s})
	if err != nil {
		return nil, err
	}

	plaintext, err := gs.Decrypt(sender, ciphertext)
	if err != nil {
		return nil, err
	}

	spb, err := s.Pickle(c.config.StorageKey)
	if err != nil {
		return nil, err
	}

	err = c.storage.SetSession(sender, []byte(spb))
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (c *Client) createAccount() (*selfcrypto.Account, error) {
	a, err := selfcrypto.AccountFromSeed(c.address, c.config.PrivateKey.Seed())
	if err != nil {
		return nil, err
	}

	err = c.publishPreKeys(a)
	if err != nil {
		return nil, err
	}

	ap, err := a.Pickle(c.config.StorageKey)
	if err != nil {
		return nil, err
	}

	return a, c.storage.SetAccount([]byte(ap))
}

func (c *Client) publishPreKeys(a *selfcrypto.Account) error {
	var pkb prekeys

	err := a.GenerateOneTimeKeys(c.config.PreKeyBundleSize)
	if err != nil {
		return err
	}

	otks, err := a.OneTimeKeys()
	if err != nil {
		return err
	}

	for k, v := range otks.Curve25519 {
		pkb = append(pkb, prekey{ID: k, Key: v})
	}

	pkbd, err := json.Marshal(pkb)
	if err != nil {
		return err
	}

	return c.pki.SetDeviceKeys(c.config.SelfID, c.config.DeviceID, pkbd)
}

func (c *Client) createOutboundSession(recipient string) (*selfcrypto.Session, error) {
	var prk prekey
	var pks pubkeys

	identity, device := getIDs(recipient)

	prkd, err := c.pki.GetDeviceKey(identity, device)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(prkd, &prk)
	if err != nil {
		return nil, err
	}

	pksd, err := c.pki.GetPublicKeys(identity)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(pksd, &pks)
	if err != nil {
		return nil, err
	}

	// TODO : support getting the right public key when devices > 1
	pkd, err := base64.RawStdEncoding.DecodeString(pks[0].Key)
	if err != nil {
		return nil, err
	}

	pkr, err := selfcrypto.Ed25519PKToCurve25519(pkd)
	if err != nil {
		return nil, err
	}

	pk := base64.RawStdEncoding.EncodeToString(pkr)

	return selfcrypto.CreateOutboundSession(c.account, recipient, pk, prk.Key)
}

func (c *Client) createInboundSession(recipient string, ciphertext []byte) (*selfcrypto.Session, error) {
	var m selfcrypto.GroupMessage

	err := json.Unmarshal(ciphertext, &m)
	if err != nil {
		return nil, err
	}

	s, err := selfcrypto.CreateInboundSession(c.account, recipient, m.Recipients[c.address])
	if err != nil {
		return nil, err
	}

	err = c.account.RemoveOneTimeKeys(s)
	if err != nil {
		return nil, err
	}

	otks, err := c.account.OneTimeKeys()
	if err != nil {
		return nil, err
	}

	if len(otks.Curve25519) < 10 {
		err = c.publishPreKeys(c.account)
		if err != nil {
			return nil, err
		}
	}

	ap, err := c.account.Pickle(c.config.StorageKey)
	if err != nil {
		return nil, err
	}

	return s, c.storage.SetAccount([]byte(ap))
}

func getIDs(recipient string) (string, string) {
	p := strings.Split(recipient, ":")
	return p[0], p[1]
}

func randInt(max int) (int, error) {
	b, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return -1, err
	}

	return int(b.Int64()), nil
}
