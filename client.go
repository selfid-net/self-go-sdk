// Copyright 2020 Self Group Ltd. All Rights Reserved.

package selfsdk

import (
	"encoding/json"
	"time"

	"github.com/joinself/self-go-sdk/authentication"
	"github.com/joinself/self-go-sdk/fact"
	"github.com/joinself/self-go-sdk/identity"
	"github.com/joinself/self-go-sdk/messaging"
)

// RestTransport defines the interface required for the sdk to perform
// operations against self's rest api
type RestTransport interface {
	Get(path string) ([]byte, error)
	Post(path string, ctype string, data []byte) ([]byte, error)
	Put(path string, ctype string, data []byte) ([]byte, error)
	Delete(path string) ([]byte, error)
}

// WebsocketTransport defines the interface required for the sdk to perform
// operations against self's websocket services
type WebsocketTransport interface {
	Send(recipients []string, data []byte) error
	Receive() (string, []byte, error)
	Command(command string, payload []byte) ([]byte, error)
	Close() error
}

// MessagingClient defines the interface required for the sdk to perform
// operations against self's messaging service
type MessagingClient interface {
	Send(recipients []string, plaintext []byte) error
	Request(recipients []string, cid string, data []byte, timeout time.Duration) (string, []byte, error)
	Register(cid string)
	Wait(cid string, timeout time.Duration) (string, []byte, error)
	Subscribe(msgType string, sub func(sender string, payload []byte))
	Command(command, selfID string, payload []byte) ([]byte, error)
	IsPermittingConnectionsFrom(selfid string) bool
	ListConnections() ([]string, error)
	Close() error
}

// PKIClient defines the interface required for the sdk to perform
// retrieving identity and device public keys from self
type PKIClient interface {
	GetHistory(selfID string) ([]json.RawMessage, error)
	GetDeviceKey(selfID, deviceID string) ([]byte, error)
	SetDeviceKeys(selfID, deviceID string, pkb []byte) error
}

// CryptoClient defines the interface required for the sdk to perform
// cryptographic operations like encrypting and decrypting messages
type CryptoClient interface {
	Encrypt(recipients []string, plaintext []byte) ([]byte, error)
	Decrypt(sender string, ciphertext []byte) ([]byte, error)
}

// CryptoStorage defines the interface required for the sdk to store and
// retrieve end to end ecryption session and account state
type CryptoStorage interface {
	GetAccount() ([]byte, error)
	SetAccount(account []byte) error
	GetSession(recipient string) ([]byte, error)
	SetSession(recipient string, session []byte) error
}

// Client handles all interactions with self services
type Client struct {
	config     Config
	connectors *Connectors
}

// New creates a new self client
func New(cfg Config) (*Client, error) {
	err := cfg.validate()
	if err != nil {
		return nil, err
	}

	err = cfg.load()
	if err != nil {
		return nil, err
	}

	client := &Client{
		config:     cfg,
		connectors: cfg.Connectors,
	}

	return client, nil
}

// FactService returns a client for working with facts
func (c *Client) FactService() *fact.Service {
	cfg := fact.Config{
		SelfID:      c.config.SelfAppID,
		DeviceID:    c.config.DeviceID,
		KeyID:       c.config.kid,
		Environment: c.config.Environment,
		PrivateKey:  c.config.sk,
		Rest:        c.connectors.Rest,
		PKI:         c.connectors.PKI,
		Messaging:   c.connectors.Messaging,
	}
	return fact.NewService(cfg)
}

// IdentityService returns a client for working with identities
func (c *Client) IdentityService() *identity.Service {
	cfg := identity.Config{
		Rest: c.connectors.Rest,
		PKI:  c.connectors.PKI,
	}
	return identity.NewService(cfg)
}

// AuthenticationService returns a client for working with authentication
func (c *Client) AuthenticationService() *authentication.Service {
	cfg := authentication.Config{
		SelfID:      c.config.SelfAppID,
		DeviceID:    c.config.DeviceID,
		KeyID:       c.config.kid,
		Environment: c.config.Environment,
		PrivateKey:  c.config.sk,
		Rest:        c.connectors.Rest,
		PKI:         c.connectors.PKI,
		Messaging:   c.connectors.Messaging,
	}

	return authentication.NewService(cfg)
}

// MessagingService returns a client for working with messages
func (c *Client) MessagingService() *messaging.Service {
	cfg := messaging.Config{
		SelfID:     c.config.SelfAppID,
		PrivateKey: c.config.sk,
		KeyID:      c.config.kid,
		Rest:       c.connectors.Rest,
		PKI:        c.connectors.PKI,
		Messaging:  c.connectors.Messaging,
	}

	return messaging.NewService(cfg)
}

// Close gracefully closes the self client
func (c *Client) Close() error {
	err := c.connectors.Websocket.Close()
	if err != nil {
		return err
	}

	return c.connectors.Messaging.Close()
}
