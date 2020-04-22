package messaging

import (
	"encoding/base64"
	"time"

	"golang.org/x/crypto/ed25519"
)

var enc = base64.RawStdEncoding

// messagingClient handles all interactions with self messaging and its users
type messagingClient interface {
	Send(recipients []string, data []byte) error
	Request(recipients []string, cid string, data []byte) (string, []byte, error)
	Subscribe(msgType string, sub func(sender string, payload []byte))
	Command(command string, payload []byte) ([]byte, error)
}

type pkiClient interface {
	GetPublicKeys(selfID string) ([]byte, error)
}

// Service handles all messaging operations
type Service struct {
	selfID    string
	sk        ed25519.PrivateKey
	pki       pkiClient
	messaging messagingClient
}

// Config stores all configuration needed by the messaging service
type Config struct {
	SelfID     string
	PrivateKey ed25519.PrivateKey
	PKI        pkiClient
	Messaging  messagingClient
}

type publickey struct {
	ID  int    `json:"id"`
	Key string `json:"key"`
}

func (p publickey) pk() ed25519.PublicKey {
	kd, _ := enc.DecodeString(p.Key)
	return ed25519.PublicKey(kd)
}

type aclrule struct {
	Source  string    `json:"acl_source"`
	Expires time.Time `json:"acl_exp"`
}

type jwsPayload struct {
	ID           string    `json:"jti"`
	Conversation string    `json:"cid"`
	Issuer       string    `json:"iss"`
	Audience     string    `json:"aud"`
	Subject      string    `json:"sub"`
	IssuedAt     time.Time `json:"iat"`
	ExpiresAt    time.Time `json:"exp"`
}

// NewService creates a new client for interacting with messaging
func NewService(cfg Config) *Service {
	return &Service{
		selfID:    cfg.SelfID,
		sk:        cfg.PrivateKey,
		pki:       cfg.PKI,
		messaging: cfg.Messaging,
	}
}
