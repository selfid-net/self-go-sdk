// Copyright 2020 Self Group Ltd. All Rights Reserved.

package transport

import (
	"golang.org/x/crypto/ed25519"

	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/joinself/self-go-sdk/pkg/ntp"
	"github.com/square/go-jose"
)

// GenerateToken generates a signed jwt token for use with self services
func GenerateToken(selfID, kid string, sk ed25519.PrivateKey) (string, error) {
	claims, err := json.Marshal(map[string]interface{}{
		"jti": uuid.New().String(),
		"cid": uuid.New().String(),
		"typ": "auth.token",
		"iss": selfID,
		"sub": selfID,
		"iat": ntp.TimeFunc().Add(-(time.Second * 5)).Unix(),
		"exp": ntp.TimeFunc().Add(time.Minute).Unix(),
	})

	if err != nil {
		return "", err
	}

	opts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": kid,
		},
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: sk}, opts)
	if err != nil {
		return "", err
	}

	signedPayload, err := signer.Sign(claims)
	if err != nil {
		return "", err
	}

	token, err := signedPayload.CompactSerialize()
	if err != nil {
		return "", err
	}

	return string(token), nil
}
