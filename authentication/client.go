package authentication

import (
	"encoding/base64"
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
	Request(recipients []string, cid string, data []byte) (string, []byte, error)
	Register(cid string)
	Send(recipients []string, data []byte) error
	Wait(cid string, timeout time.Duration) (string, []byte, error)
}

// PKIClient handles all interactions with selfs public key infrastructure
type pkiClient interface {
	GetPublicKeys(selfID string) ([]byte, error)
}

type publickey struct {
	ID  int    `json:"id"`
	Key string `json:"key"`
}

func (p publickey) pk() ed25519.PublicKey {
	kd, _ := enc.DecodeString(p.Key)
	return ed25519.PublicKey(kd)
}

// Service handles all fact operations
type Service struct {
	api         restTransport
	pki         pkiClient
	messaging   messagingClient
	selfID      string
	deviceID    string
	environment string
	expiry      time.Duration
	sk          ed25519.PrivateKey
}

// Config stores all configuration needed by the authentication service
type Config struct {
	SelfID      string
	DeviceID    string
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
		environment: config.Environment,
		sk:          config.PrivateKey,
		api:         config.Rest,
		pki:         config.PKI,
		messaging:   config.Messaging,
		expiry:      time.Minute,
	}
}
