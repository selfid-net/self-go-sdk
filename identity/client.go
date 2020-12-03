// Copyright 2020 Self Group Ltd. All Rights Reserved.

package identity

import "encoding/json"

// restTransport handles all interactions with the self api
type restTransport interface {
	Get(path string) ([]byte, error)
}

// PKIClient handles all interactions with handling public keys
type pkiClient interface {
	GetHistory(selfID string) ([]json.RawMessage, error)
}

// Service handles all fact operations
type Service struct {
	api restTransport
	pki pkiClient
}

// Config stores all configuration needed by the identity service
type Config struct {
	Rest restTransport
	PKI  pkiClient
}

// NewService creates a new client for interacting with facts
func NewService(cfg Config) *Service {
	return &Service{
		api: cfg.Rest,
		pki: cfg.PKI,
	}
}
