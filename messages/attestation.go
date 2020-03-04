package messages

import (
	"errors"

	"github.com/square/go-jose"
	"github.com/tidwall/gjson"
	"golang.org/x/crypto/ed25519"

	"encoding/json"
)

// Attestation holds an attestation about a fact
type Attestation json.RawMessage

// JWS returns the attestation as a jws
func (a *Attestation) JWS() (*jose.JSONWebSignature, error) {
	return jose.ParseSigned(string(*a))
}

// Issuer returns the identity that issued and signed the attestation
func (a *Attestation) Issuer() string {
	return a.value("iss")
}

// Validate validates an attestation against a set of identtiy keys
func (a *Attestation) Validate(keys []ed25519.PublicKey) error {
	if len(keys) < 1 {
		return errors.New("no valid identity keys provided")
	}

	jws, err := a.JWS()
	if err != nil {
		return err
	}

	for _, k := range keys {
		_, err = jws.Verify(k)
		if err == nil {
			return nil
		}
	}

	return errors.New("attestation has not been signed by a valid key")
}

func (a *Attestation) value(key string) string {
	jws, err := a.JWS()
	if err != nil {
		return ""
	}

	payload := jws.UnsafePayloadWithoutVerification()

	return gjson.GetBytes(payload, key).String()
}
