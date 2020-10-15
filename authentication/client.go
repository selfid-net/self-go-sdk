package authentication

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"golang.org/x/crypto/ed25519"
)

var enc = base64.RawStdEncoding

// restTransport handles all interactions with the self api
type restTransport interface {
	Get(path string) ([]byte, error)
}

// MessagingClient handles all interactions with self messaging and its users
type messagingClient interface {
	Request(recipients []string, cid string, data []byte, timeout time.Duration) (string, []byte, error)
	Register(cid string)
	Send(recipients []string, data []byte) error
	Wait(cid string, timeout time.Duration) (string, []byte, error)
	Subscribe(msgType string, sub func(sender string, payload []byte))
	IsPermittingConnectionsFrom(selfid string) bool
}

// PKIClient handles all interactions with selfs public key infrastructure
type pkiClient interface {
	GetHistory(selfID string) ([]json.RawMessage, error)
}

// Service handles all fact operations
type Service struct {
	api         restTransport
	pki         pkiClient
	messaging   messagingClient
	selfID      string
	deviceID    string
	keyID       string
	environment string
	expiry      time.Duration
	sk          ed25519.PrivateKey
}

// Config stores all configuration needed by the authentication service
type Config struct {
	SelfID      string
	DeviceID    string
	KeyID       string
	Environment string
	PrivateKey  ed25519.PrivateKey
	Rest        restTransport
	Messaging   messagingClient
	PKI         pkiClient
}

// NewService creates a new client for interacting with facts
func NewService(config Config) *Service {
	return &Service{
		selfID:      config.SelfID,
		deviceID:    config.DeviceID,
		keyID:       config.KeyID,
		environment: config.Environment,
		sk:          config.PrivateKey,
		api:         config.Rest,
		pki:         config.PKI,
		messaging:   config.Messaging,
		expiry:      time.Minute,
	}
}
