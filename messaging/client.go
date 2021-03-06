// Copyright 2020 Self Group Ltd. All Rights Reserved.

package messaging

import (
	"encoding/json"
	"time"

	"golang.org/x/crypto/ed25519"
)

// restTransport handles all interactions with the self api
type restTransport interface {
	Get(path string) ([]byte, error)
}

// messagingClient handles all interactions with self messaging and its users
type messagingClient interface {
	Send(recipients []string, data []byte) error
	Request(recipients []string, cid string, data []byte, timeout time.Duration) (string, []byte, error)
	Subscribe(msgType string, sub func(sender string, payload []byte))
	Command(command, selfID string, payload []byte) ([]byte, error)
	ListConnections() ([]string, error)
}

type pkiClient interface {
	GetHistory(selfID string) ([]json.RawMessage, error)
}

// Service handles all messaging operations
type Service struct {
	selfID    string
	keyID     string
	sk        ed25519.PrivateKey
	api       restTransport
	pki       pkiClient
	messaging messagingClient
}

// Config stores all configuration needed by the messaging service
type Config struct {
	SelfID     string
	KeyID      string
	PrivateKey ed25519.PrivateKey
	PKI        pkiClient
	Messaging  messagingClient
	Rest       restTransport
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
		keyID:     cfg.KeyID,
		sk:        cfg.PrivateKey,
		api:       cfg.Rest,
		pki:       cfg.PKI,
		messaging: cfg.Messaging,
	}
}
