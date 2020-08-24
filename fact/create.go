package fact

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/joinself/self-go-sdk/pkg/ntp"
	"gopkg.in/square/go-jose.v2"
)

// Attest creates an attested fact about a self identity
func (s Service) Attest(selfID string, facts []Fact) ([]json.RawMessage, error) {
	attestations := make([]json.RawMessage, len(facts))

	opts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": s.keyID,
		},
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: s.sk}, opts)
	if err != nil {
		return nil, err
	}

	for i, f := range facts {
		if len(f.Sources) != 0 {
			return nil, ErrFactBadSource
		}

		err = f.validate()
		if err != nil {
			return nil, err
		}

		payload, err := json.Marshal(map[string]string{
			"jti":    uuid.New().String(),
			"iss":    s.selfID,
			"sub":    selfID,
			"iat":    ntp.TimeFunc().Format(time.RFC3339),
			"source": f.Sources[0],
			f.Fact:   f.AttestedValue,
		})

		if err != nil {
			return nil, err
		}

		attestation, err := signer.Sign(payload)
		if err != nil {
			return nil, err
		}

		attestations[i] = json.RawMessage(attestation.FullSerialize())
	}

	return attestations, nil
}
