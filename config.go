// Copyright 2020 Self Group Ltd. All Rights Reserved.

package selfsdk

import (
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/joinself/self-go-sdk/pkg/crypto"
	"github.com/joinself/self-go-sdk/pkg/messaging"
	"github.com/joinself/self-go-sdk/pkg/pki"
	"github.com/joinself/self-go-sdk/pkg/transport"
	"golang.org/x/crypto/ed25519"
)

var (
	defaultAPIURL               = "https://api.joinself.com"
	defaultMessagingURL         = "wss://messaging.joinself.com/v1/messaging"
	defaultReconnectionAttempts = 10
	defaultTCPDeadline          = time.Second * 5
	defaultRequestTimeout       = time.Second * 5
	defaultInboxSize            = 256

	decoder = base64.RawStdEncoding
)

// Connectors stores all connectors for working with different self api's
type Connectors struct {
	Rest      RestTransport
	Websocket WebsocketTransport
	Messaging MessagingClient
	PKI       PKIClient
	Crypto    CryptoClient
	Storage   CryptoStorage
}

// Config configuration options for the sdk
type Config struct {
	SelfAppID            string
	SelfAppDeviceSecret  string
	StorageKey           string
	DeviceID             string
	StorageDir           string
	APIURL               string
	MessagingURL         string
	Environment          string
	ReconnectionAttempts int
	TCPDeadline          time.Duration
	RequestTimeout       time.Duration
	Connectors           *Connectors
	offsetStorageDir     string
	cryptoStorageDir     string
	kid                  string
	sk                   ed25519.PrivateKey
}

type debugCryptoClient struct{}

func (d *debugCryptoClient) Encrypt(recipients []string, plaintext []byte) ([]byte, error) {
	return plaintext, nil
}

func (d *debugCryptoClient) Decrypt(sender string, ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}

func (c Config) validate() error {
	if c.SelfAppID == "" {
		return errors.New("config must specify the self app id")
	}

	if c.SelfAppDeviceSecret == "" {
		return errors.New("config must specify an app device secret key")
	}

	if len(strings.Split(c.SelfAppDeviceSecret, ":")) < 2 {
		return errors.New("config must specify an app device secret key")
	}

	if c.StorageKey == "" {
		return errors.New("config must specify a key to encrypt storage")
	}

	if c.StorageDir == "" {
		return errors.New("config must specify a storage directory")
	}

	return nil
}

func (c *Config) load() error {
	if c.Connectors == nil {
		c.Connectors = &Connectors{}
	}

	if c.DeviceID == "" {
		c.DeviceID = "1"
	}

	if c.Environment != "" {
		if c.APIURL == "" {
			c.APIURL = "https://api." + c.Environment + ".joinself.com"
		}

		if c.MessagingURL == "" {
			c.MessagingURL = "wss://messaging." + c.Environment + ".joinself.com/v1/messaging"
		}
	}

	if c.APIURL == "" {
		c.APIURL = defaultAPIURL
	}

	if c.MessagingURL == "" {
		c.MessagingURL = defaultMessagingURL
	}

	if c.ReconnectionAttempts != -1 {
		c.ReconnectionAttempts = defaultReconnectionAttempts
	}

	if c.TCPDeadline == 0 {
		c.TCPDeadline = defaultTCPDeadline
	}

	if c.RequestTimeout == 0 {
		c.RequestTimeout = defaultRequestTimeout
	}

	kp := strings.Split(c.SelfAppDeviceSecret, ":")

	skData, err := decoder.DecodeString(kp[1])
	if err != nil {
		return errors.New("could not decode private key")
	}

	c.sk = ed25519.NewKeyFromSeed(skData)
	c.kid = kp[0]

	// attempt to migrate storage directory if needed
	err = c.migrateStorage()
	if err != nil {
		return err
	}

	// loading connectors should be done in order due to dependencies
	err = c.loadRestConnector()
	if err != nil {
		return err
	}

	err = c.loadWebsocketConnector()
	if err != nil {
		return err
	}

	err = c.loadStorageConnector()
	if err != nil {
		return err
	}

	err = c.loadPKIConnector()
	if err != nil {
		return err
	}

	err = c.loadCryptoConnector()
	if err != nil {
		return err
	}

	return c.loadMessagingConnector()
}

func (c Config) loadRestConnector() error {
	if c.Connectors.Rest != nil {
		return nil
	}

	cfg := transport.RestConfig{
		Client: &http.Client{
			Transport: &http.Transport{
				Dial: (&net.Dialer{
					Timeout:   defaultTCPDeadline,
					KeepAlive: defaultTCPDeadline / 2,
				}).Dial,
			},
		},
		APIURL:     c.APIURL,
		SelfID:     c.SelfAppID,
		KeyID:      c.kid,
		PrivateKey: c.sk,
	}

	rest, err := transport.NewRest(cfg)
	if err != nil {
		return err
	}

	c.Connectors.Rest = rest

	return nil
}

func (c Config) loadWebsocketConnector() error {
	if c.Connectors.Websocket != nil {
		return nil
	}

	cfg := transport.WebsocketConfig{
		MessagingURL: c.MessagingURL,
		StorageDir:   c.offsetStorageDir,
		SelfID:       c.SelfAppID,
		KeyID:        c.kid,
		DeviceID:     c.DeviceID,
		PrivateKey:   c.sk,
		TCPDeadline:  defaultTCPDeadline,
		InboxSize:    defaultInboxSize,
	}

	ws, err := transport.NewWebsocket(cfg)
	if err != nil {
		return err
	}

	c.Connectors.Websocket = ws

	return nil
}

func (c Config) loadStorageConnector() error {
	if c.Connectors.Storage != nil {
		return nil
	}

	cfg := crypto.StorageConfig{
		StorageDir: c.cryptoStorageDir,
	}

	client, err := crypto.NewFileStorage(cfg)
	if err != nil {
		return err
	}

	c.Connectors.Storage = client

	return nil
}

func (c Config) loadPKIConnector() error {
	if c.Connectors.PKI != nil {
		return nil
	}

	cfg := pki.Config{
		APIURL:     c.APIURL,
		SelfID:     c.SelfAppID,
		PrivateKey: c.sk,
		Transport:  c.Connectors.Rest,
	}

	client, err := pki.New(cfg)
	if err != nil {
		return err
	}

	c.Connectors.PKI = client

	return nil
}

func (c Config) loadCryptoConnector() error {
	if c.Connectors.Crypto != nil {
		return nil
	}

	cfg := crypto.Config{
		SelfID:     c.SelfAppID,
		DeviceID:   c.DeviceID,
		PrivateKey: c.sk,
		StorageKey: c.StorageKey,
		Storage:    c.Connectors.Storage,
		PKI:        c.Connectors.PKI,
	}

	client, err := crypto.New(cfg)
	if err != nil {
		return err
	}

	c.Connectors.Crypto = client

	return nil
}

func (c Config) loadMessagingConnector() error {
	if c.Connectors.Messaging != nil {
		return nil
	}

	cfg := messaging.Config{
		PrivateKey: c.sk,
		Crypto:     c.Connectors.Crypto,
		Transport:  c.Connectors.Websocket,
	}

	client, err := messaging.New(cfg)
	if err != nil {
		return err
	}

	c.Connectors.Messaging = client

	return nil
}

func (c *Config) migrateStorage() error {
	var sessions []string
	var offsetFile string

	c.offsetStorageDir = filepath.Join(c.StorageDir, "apps", c.SelfAppID, "devices", c.DeviceID)
	c.cryptoStorageDir = filepath.Join(c.StorageDir, "apps", c.SelfAppID, "devices", c.DeviceID, "keys", c.kid)

	err := os.MkdirAll(c.cryptoStorageDir, 0744)
	if err != nil {
		return err
	}

	// check for any files stored in the old structure and move them into the correct directories
	err = filepath.Walk(c.StorageDir, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}

		np := strings.Split(info.Name(), ".")

		if len(np) < 2 {
			return nil
		}

		if np[1] == "offset" && filepath.Dir(path) == c.StorageDir {
			if offsetFile != "" {
				return errors.New("multiple offset files found. please remove the old offset file")
			}

			offsetFile = info.Name()
		}

		if strings.Contains(np[0], "-session") && np[1] == "pickle" {
			sessions = append(sessions, info.Name())
		}

		return nil
	})

	if err != nil {
		return err
	}

	if offsetFile == "" {
		return nil
	}

	err = os.Rename(filepath.Join(c.StorageDir, offsetFile), filepath.Join(c.offsetStorageDir, offsetFile))
	if err != nil {
		return err
	}

	err = os.Rename(filepath.Join(c.StorageDir, "account.pickle"), filepath.Join(c.cryptoStorageDir, "account.pickle"))
	if err != nil {
		return err
	}

	for _, s := range sessions {
		err = os.Rename(filepath.Join(c.StorageDir, s), filepath.Join(c.cryptoStorageDir, s))
		if err != nil {
			return err
		}
	}

	return nil
}

func (c Config) privateKey() ed25519.PrivateKey {
	return c.sk
}
