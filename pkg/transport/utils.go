package transport

import (
	"encoding/base64"

	"golang.org/x/crypto/ed25519"

	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/selfid-net/self-go-sdk/pkg/ntp"
	"github.com/square/go-jose"
)

var (
	decoder    = base64.RawStdEncoding
	urlDecoder = base64.RawURLEncoding
)

// GenerateToken generates a signed jwt token for use with self services
func GenerateToken(selfID string, sk ed25519.PrivateKey) (string, error) {
	claims, err := json.Marshal(map[string]interface{}{
		"jti": uuid.New().String(),
		"cid": uuid.New().String(),
		"typ": "auth.token",
		"iss": selfID,
		"sub": selfID,
		"iat": ntp.TimeFunc().Add(-(time.Second * 5)).Unix(),
		"exp": ntp.TimeFunc().Add(time.Minute).Unix(),
	})

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: sk}, nil)
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
