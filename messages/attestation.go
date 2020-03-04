package messages

import (
	"errors"

	"github.com/square/go-jose"
	"github.com/tidwall/gjson"
	"golang.org/x/crypto/ed25519"
)

// Attestation holds an attestation about a fact
type Attestation struct {
	jws *jose.JSONWebSignature
}

// UnmarshalJSON custom unmarshal function
func (a *Attestation) UnmarshalJSON(b []byte) error {
	jws, err := jose.ParseSigned(string(b))
	if err != nil {
		return err
	}

	a.jws = jws

	return nil
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

	for _, k := range keys {
		_, err := a.jws.Verify(k)
		if err == nil {
			return nil
		}
	}

	return errors.New("attestation has not been signed by a valid key")
}

func (a *Attestation) value(key string) string {
	payload := a.jws.UnsafePayloadWithoutVerification()
	return gjson.GetBytes(payload, key).String()
}
