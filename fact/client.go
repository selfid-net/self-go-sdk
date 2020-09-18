package fact

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"golang.org/x/crypto/ed25519"
)

var (
	defaultRequestTimeout = time.Minute * 15

	enc = base64.RawStdEncoding
)

// restTransport handles all interactions with the self api
type restTransport interface {
	Get(path string) ([]byte, error)
}

// MessagingClient handles all interactions with self messaging and its users
type messagingClient interface {
	Request(recipients []string, cid string, data []byte, timeout time.Duration) (string, []byte, error)
	Send(recipients []string, data []byte) error
	Register(cid string)
	Wait(cid string, timeout time.Duration) (string, []byte, error)
}

type pkiClient interface {
	GetHistory(selfID string) ([]json.RawMessage, error)
}

type device struct {
	ID string `json:"device_id"`
}

// Service handles all fact operations
type Service struct {
	selfID      string
	deviceID    string
	keyID       string
	environment string
	sk          ed25519.PrivateKey
	api         restTransport
	pki         pkiClient
	messaging   messagingClient
}

// Config stores all configuration needed by the fact service
type Config struct {
	SelfID      string
	DeviceID    string
	KeyID       string
	Environment string
	PrivateKey  ed25519.PrivateKey
	Rest        restTransport
	PKI         pkiClient
	Messaging   messagingClient
}

// NewService creates a new client for interacting with facts
func NewService(cfg Config) *Service {
	return &Service{
		selfID:      cfg.SelfID,
		deviceID:    cfg.DeviceID,
		keyID:       cfg.KeyID,
		environment: cfg.Environment,
		sk:          cfg.PrivateKey,
		api:         cfg.Rest,
		pki:         cfg.PKI,
		messaging:   cfg.Messaging,
	}
}
