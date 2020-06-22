package fact

import (
	"encoding/base64"
	"time"

	"golang.org/x/crypto/ed25519"
)

var (
	defaultRequestTimeout = time.Minute * 5

	enc = base64.RawStdEncoding
)

// restTransport handles all interactions with the self api
type restTransport interface {
	Get(path string) ([]byte, error)
}

// MessagingClient handles all interactions with self messaging and its users
type messagingClient interface {
	Request(recipients []string, cid string, data []byte) (string, []byte, error)
	Register(cid string)
	Wait(cid string, timeout time.Duration) (string, []byte, error)
}

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

type device struct {
	ID string `json:"device_id"`
}

// Service handles all fact operations
type Service struct {
	selfID      string
	deviceID    string
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
		environment: cfg.Environment,
		sk:          cfg.PrivateKey,
		api:         cfg.Rest,
		pki:         cfg.PKI,
		messaging:   cfg.Messaging,
	}
}
