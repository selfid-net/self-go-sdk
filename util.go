package selfsdk

import (
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/tidwall/gjson"
	"golang.org/x/crypto/ed25519"
	"gopkg.in/square/go-jose.v2"
)

// verifies a jws message and returns its payload
func verify(data []byte, keys []ed25519.PublicKey) ([]byte, error) {
	for _, k := range keys {
		jws, err := jose.ParseSigned(string(data))
		if err != nil {
			return nil, err
		}

		payload, err := jws.Verify(k)
		if err == nil {
			return payload, nil
		}
	}

	return nil, errors.New("jws verification failed")
}

// validate validates a JWS attestations signature and that it matches
// a given subjects self ID
func validate(subjectID string, data []byte, kc *keyCache) ([]byte, error) {
	var claim map[string]interface{}

	jws, err := jose.ParseSigned(string(data))
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &claim)
	if err != nil {
		return nil, err
	}

	sub, ok := claim["sub"].(string)
	if !ok {
		return nil, errors.New("jws has an invalid subject")
	}

	iss, ok := claim["iss"].(string)
	if !ok {
		return nil, errors.New("jws has an invalid issuer")
	}

	if sub != subjectID {
		return nil, errors.New("jws subject does not match")
	}

	keys, err := kc.get(iss)
	if err != nil {
		return nil, err
	}

	for _, k := range keys {
		payload, err := jws.Verify(k)
		if err == nil {
			return payload, nil
		}
	}

	return nil, errors.New("jws verification failed")
}

func getJWSValue(data []byte, field string) string {
	encodedPayload := gjson.GetBytes(data, "payload").String()
	if encodedPayload == "" {
		return encodedPayload
	}

	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return ""
	}

	return gjson.GetBytes(payload, field).String()
}
