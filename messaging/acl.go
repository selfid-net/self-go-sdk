package messaging

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/joinself/self-go-sdk/pkg/ntp"
	"github.com/square/go-jose"
)

// PermitConnection permits messages from a self ID
func (c Service) PermitConnection(selfID string) error {
	payload, err := json.Marshal(map[string]string{
		"jti":        uuid.New().String(),
		"cid":        uuid.New().String(),
		"typ":        "acl.permit",
		"iss":        c.selfID,
		"sub":        c.selfID,
		"iat":        ntp.TimeFunc().Format(time.RFC3339),
		"exp":        ntp.TimeFunc().Add(time.Minute).Format(time.RFC3339),
		"acl_source": selfID,
	})

	if err != nil {
		return err
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: c.sk}, nil)
	if err != nil {
		return err
	}

	signedPayload, err := signer.Sign(payload)
	if err != nil {
		return err
	}

	command := signedPayload.FullSerialize()

	_, err = c.messaging.Command("acl.permit", []byte(command))

	return err
}

// RevokeConnection denies and removes any exisitng permissions for a self ID
func (c Service) RevokeConnection(selfID string) error {
	payload, err := json.Marshal(map[string]string{
		"jti":        uuid.New().String(),
		"cid":        uuid.New().String(),
		"typ":        "acl.revoke",
		"iss":        c.selfID,
		"sub":        c.selfID,
		"iat":        ntp.TimeFunc().Format(time.RFC3339),
		"exp":        ntp.TimeFunc().Add(time.Minute).Format(time.RFC3339),
		"acl_source": selfID,
	})

	if err != nil {
		return err
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: c.sk}, nil)
	if err != nil {
		return err
	}

	signedPayload, err := signer.Sign(payload)
	if err != nil {
		return err
	}

	command := signedPayload.FullSerialize()

	_, err = c.messaging.Command("acl.revoke", []byte(command))

	return err
}

// ListConnections lists all self IDs that are permitted to send messages
func (c Service) ListConnections() ([]string, error) {
	var rules []aclrule

	resp, err := c.messaging.Command("acl.list", nil)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(resp, &rules)
	if err != nil {
		return nil, err
	}

	permitted := make([]string, len(rules))

	for i, r := range rules {
		permitted[i] = r.Source
	}

	return permitted, nil
}
