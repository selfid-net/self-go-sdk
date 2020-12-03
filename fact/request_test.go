// Copyright 2020 Self Group Ltd. All Rights Reserved.

package fact

import (
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/joinself/self-go-sdk/pkg/ntp"
	"github.com/square/go-jose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

func TestRequest(t *testing.T) {
	r, cfg := setup(t)

	s := NewService(cfg)

	fr := &FactRequest{
		SelfID: "1234567890",
		Expiry: time.Millisecond,
		Facts: []Fact{
			{
				Fact:    FactGivenNames,
				Sources: []string{SourceDrivingLicense},
			},
			{
				Fact:    FactSurname,
				Sources: []string{SourceDrivingLicense},
			},
		},
	}

	ipk, isk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	apk, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	r.addpk("1234567890", isk, ipk)
	r.addpk("test-attester", ask, apk)
	r.path = "/v1/identities/1234567890/devices"
	r.payload = []byte(`["1", "2"]`)
	r.secondaryPaths["/v1/apps/test"] = []byte(`{"paid_actions":true}`)

	var called bool

	r.responder = func(recipients []string, req []byte) (string, []byte, error) {
		called = true

		jws, err := jose.ParseSigned(string(req))
		require.Nil(t, err)

		payload, err := jws.Verify(s.sk.Public())
		require.Nil(t, err)

		var m standardresponse
		err = json.Unmarshal(payload, &m)
		require.Nil(t, err)

		assert.NotEmpty(t, m.ID)
		assert.NotEmpty(t, m.Conversation)
		assert.NotZero(t, m.IssuedAt)
		assert.NotZero(t, m.ExpiresAt)
		assert.Equal(t, RequestInformation, m.Type)
		assert.Equal(t, "test", m.Issuer)
		assert.Equal(t, fr.SelfID, m.Subject)
		assert.Equal(t, fr.SelfID, m.Audience)
		assert.Equal(t, fr.Description, m.Description)
		require.Len(t, m.Facts, 2)
		assert.Equal(t, FactGivenNames, m.Facts[0].Fact)
		assert.Equal(t, []string{SourceDrivingLicense}, m.Facts[0].Sources)
		assert.Equal(t, FactSurname, m.Facts[1].Fact)
		assert.Equal(t, []string{SourceDrivingLicense}, m.Facts[1].Sources)

		m.Type = ResponseInformation
		m.Issuer = fr.SelfID
		m.Subject = fr.SelfID
		m.Audience = "test"
		m.IssuedAt = ntp.TimeFunc()
		m.ExpiresAt = ntp.TimeFunc().Add(time.Minute)
		m.Status = "accepted"

		at, err := json.Marshal(map[string]string{
			"jti":         uuid.New().String(),
			"sub":         fr.SelfID,
			"iss":         "test-attester",
			"iat":         ntp.TimeFunc().Format(time.RFC3339),
			"source":      SourceDrivingLicense,
			"given_names": "pontiac",
		})

		opts := &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": "1",
			},
		}

		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: ask}, opts)
		require.Nil(t, err)

		attestation, err := s.Sign(at)
		require.Nil(t, err)

		m.Facts[0].Attestations = append(m.Facts[0].Attestations, []byte(attestation.FullSerialize()))

		at, err = json.Marshal(map[string]string{
			"jti":     uuid.New().String(),
			"sub":     fr.SelfID,
			"iss":     "test-attester",
			"iat":     ntp.TimeFunc().Format(time.RFC3339),
			"source":  SourceDrivingLicense,
			"surname": "bandit",
		})

		s, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: ask}, opts)
		require.Nil(t, err)

		attestation, err = s.Sign(at)
		require.Nil(t, err)

		m.Facts[1].Attestations = append(m.Facts[1].Attestations, []byte(attestation.FullSerialize()))

		resp, err := json.Marshal(m)
		require.Nil(t, err)

		s, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: isk}, opts)
		require.Nil(t, err)

		response, err := s.Sign(resp)
		require.Nil(t, err)

		return fr.SelfID + ":1", []byte(response.FullSerialize()), nil
	}

	resp, err := s.Request(fr)
	require.Nil(t, err)
	assert.True(t, called)
	assert.Len(t, resp.Facts, 2)
	assert.Equal(t, []string{"1234567890:1", "1234567890:2"}, r.recipients)
}

func TestRequestTimeout(t *testing.T) {
	r, cfg := setup(t)

	s := NewService(cfg)

	fr := &FactRequest{
		SelfID: "1234567890",
		Expiry: time.Millisecond,
		Facts: []Fact{
			{
				Fact:    FactGivenNames,
				Sources: []string{SourceDrivingLicense},
			},
			{
				Fact:    FactSurname,
				Sources: []string{SourceDrivingLicense},
			},
		},
	}

	ipk, isk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	apk, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	r.addpk("1234567890", isk, ipk)
	r.addpk("test-attester", ask, apk)
	r.path = "/v1/identities/1234567890/devices"
	r.payload = []byte(`["1", "2"]`)
	r.secondaryPaths["/v1/apps/test"] = []byte(`{"paid_actions":true}`)

	var called bool

	r.responder = func(recipients []string, req []byte) (string, []byte, error) {
		called = true

		jws, err := jose.ParseSigned(string(req))
		require.Nil(t, err)

		payload, err := jws.Verify(s.sk.Public())
		require.Nil(t, err)

		var m standardresponse
		err = json.Unmarshal(payload, &m)
		require.Nil(t, err)

		assert.NotEmpty(t, m.ID)
		assert.NotEmpty(t, m.Conversation)
		assert.NotZero(t, m.IssuedAt)
		assert.NotZero(t, m.ExpiresAt)
		assert.Equal(t, RequestInformation, m.Type)
		assert.Equal(t, "test", m.Issuer)
		assert.Equal(t, fr.SelfID, m.Subject)
		assert.Equal(t, fr.SelfID, m.Audience)
		assert.Equal(t, fr.Description, m.Description)
		require.Len(t, m.Facts, 2)
		assert.Equal(t, FactGivenNames, m.Facts[0].Fact)
		assert.Equal(t, []string{SourceDrivingLicense}, m.Facts[0].Sources)
		assert.Equal(t, FactSurname, m.Facts[1].Fact)
		assert.Equal(t, []string{SourceDrivingLicense}, m.Facts[1].Sources)

		return "", nil, ErrRequestTimeout
	}

	_, err = s.Request(fr)
	require.NotNil(t, err)
	assert.True(t, called)
}

func TestRequestBadAttestation(t *testing.T) {
	r, cfg := setup(t)

	s := NewService(cfg)

	fr := &FactRequest{
		SelfID: "1234567890",
		Expiry: time.Millisecond,
		Facts: []Fact{
			{
				Fact:    FactGivenNames,
				Sources: []string{SourceDrivingLicense},
			},
			{
				Fact:    FactSurname,
				Sources: []string{SourceDrivingLicense},
			},
		},
	}

	ipk, isk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	apk, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	r.addpk("1234567890", isk, ipk)
	r.addpk("test-attester", ask, apk)
	r.path = "/v1/identities/1234567890/devices"
	r.payload = []byte(`["1", "2"]`)
	r.secondaryPaths["/v1/apps/test"] = []byte(`{"paid_actions":true}`)

	var called bool

	r.responder = func(recipients []string, req []byte) (string, []byte, error) {
		called = true

		jws, err := jose.ParseSigned(string(req))
		require.Nil(t, err)

		payload, err := jws.Verify(s.sk.Public())
		require.Nil(t, err)

		var m standardresponse
		err = json.Unmarshal(payload, &m)
		require.Nil(t, err)

		assert.NotEmpty(t, m.ID)
		assert.NotEmpty(t, m.Conversation)
		assert.NotZero(t, m.IssuedAt)
		assert.NotZero(t, m.ExpiresAt)
		assert.Equal(t, RequestInformation, m.Type)
		assert.Equal(t, "test", m.Issuer)
		assert.Equal(t, fr.SelfID, m.Subject)
		assert.Equal(t, fr.SelfID, m.Audience)
		assert.Equal(t, fr.Description, m.Description)
		require.Len(t, m.Facts, 2)
		assert.Equal(t, FactGivenNames, m.Facts[0].Fact)
		assert.Equal(t, []string{SourceDrivingLicense}, m.Facts[0].Sources)
		assert.Equal(t, FactSurname, m.Facts[1].Fact)
		assert.Equal(t, []string{SourceDrivingLicense}, m.Facts[1].Sources)

		m.Type = ResponseInformation
		m.Issuer = fr.SelfID
		m.Subject = fr.SelfID
		m.Audience = "test"
		m.IssuedAt = ntp.TimeFunc()
		m.ExpiresAt = ntp.TimeFunc().Add(time.Minute)
		m.Status = "accepted"

		at, err := json.Marshal(map[string]string{
			"jti":         uuid.New().String(),
			"sub":         fr.SelfID,
			"iss":         "test-attester",
			"iat":         ntp.TimeFunc().Format(time.RFC3339),
			"source":      SourceDrivingLicense,
			"given_names": "pontiac",
		})

		opts := &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": "1",
			},
		}

		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: ask}, opts)
		require.Nil(t, err)

		attestation, err := s.Sign(at)
		require.Nil(t, err)

		m.Facts[0].Attestations = append(m.Facts[0].Attestations, []byte(attestation.FullSerialize()))

		at, err = json.Marshal(map[string]string{
			"jti":     uuid.New().String(),
			"sub":     "bad-id",
			"iss":     "test-attester",
			"iat":     ntp.TimeFunc().Format(time.RFC3339),
			"source":  SourceDrivingLicense,
			"surname": "bandit",
		})

		s, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: ask}, opts)
		require.Nil(t, err)

		attestation, err = s.Sign(at)
		require.Nil(t, err)

		m.Facts[1].Attestations = append(m.Facts[1].Attestations, []byte(attestation.FullSerialize()))

		resp, err := json.Marshal(m)
		require.Nil(t, err)

		s, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: isk}, opts)
		require.Nil(t, err)

		response, err := s.Sign(resp)
		require.Nil(t, err)

		return fr.SelfID + ":1", []byte(response.FullSerialize()), nil
	}

	_, err = s.Request(fr)
	require.NotNil(t, err)
	assert.True(t, called)
}

func TestRequestBadStatus(t *testing.T) {
	r, cfg := setup(t)

	s := NewService(cfg)

	fr := &FactRequest{
		SelfID: "1234567890",
		Expiry: time.Millisecond,
		Facts: []Fact{
			{
				Fact:    FactGivenNames,
				Sources: []string{SourceDrivingLicense},
			},
			{
				Fact:    FactSurname,
				Sources: []string{SourceDrivingLicense},
			},
		},
	}

	ipk, isk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	apk, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	r.addpk("1234567890", isk, ipk)
	r.addpk("test-attester", ask, apk)
	r.path = "/v1/identities/1234567890/devices"
	r.payload = []byte(`["1", "2"]`)
	r.secondaryPaths["/v1/apps/test"] = []byte(`{"paid_actions":true}`)

	var called bool

	r.responder = func(recipients []string, req []byte) (string, []byte, error) {
		called = true

		jws, err := jose.ParseSigned(string(req))
		require.Nil(t, err)

		payload, err := jws.Verify(s.sk.Public())
		require.Nil(t, err)

		var m standardresponse
		err = json.Unmarshal(payload, &m)
		require.Nil(t, err)

		assert.NotEmpty(t, m.ID)
		assert.NotEmpty(t, m.Conversation)
		assert.NotZero(t, m.IssuedAt)
		assert.NotZero(t, m.ExpiresAt)
		assert.Equal(t, RequestInformation, m.Type)
		assert.Equal(t, "test", m.Issuer)
		assert.Equal(t, fr.SelfID, m.Subject)
		assert.Equal(t, fr.SelfID, m.Audience)
		assert.Equal(t, fr.Description, m.Description)
		require.Len(t, m.Facts, 2)
		assert.Equal(t, FactGivenNames, m.Facts[0].Fact)
		assert.Equal(t, []string{SourceDrivingLicense}, m.Facts[0].Sources)
		assert.Equal(t, FactSurname, m.Facts[1].Fact)
		assert.Equal(t, []string{SourceDrivingLicense}, m.Facts[1].Sources)

		m.Type = ResponseInformation
		m.Issuer = fr.SelfID
		m.Subject = fr.SelfID
		m.Audience = "test"
		m.IssuedAt = ntp.TimeFunc()
		m.ExpiresAt = ntp.TimeFunc().Add(time.Minute)
		m.Status = "rejected"

		at, err := json.Marshal(map[string]string{
			"jti":         uuid.New().String(),
			"sub":         fr.SelfID,
			"iss":         "test-attester",
			"iat":         ntp.TimeFunc().Format(time.RFC3339),
			"source":      SourceDrivingLicense,
			"given_names": "pontiac",
		})

		opts := &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": "1",
			},
		}

		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: ask}, opts)
		require.Nil(t, err)

		attestation, err := s.Sign(at)
		require.Nil(t, err)

		m.Facts[0].Attestations = append(m.Facts[0].Attestations, []byte(attestation.FullSerialize()))

		at, err = json.Marshal(map[string]string{
			"jti":     uuid.New().String(),
			"sub":     fr.SelfID,
			"iss":     "test-attester",
			"iat":     ntp.TimeFunc().Format(time.RFC3339),
			"source":  SourceDrivingLicense,
			"surname": "bandit",
		})

		s, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: ask}, opts)
		require.Nil(t, err)

		attestation, err = s.Sign(at)
		require.Nil(t, err)

		m.Facts[1].Attestations = append(m.Facts[1].Attestations, []byte(attestation.FullSerialize()))

		resp, err := json.Marshal(m)
		require.Nil(t, err)

		s, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: isk}, opts)
		require.Nil(t, err)

		response, err := s.Sign(resp)
		require.Nil(t, err)

		return fr.SelfID + ":1", []byte(response.FullSerialize()), nil
	}

	_, err = s.Request(fr)
	require.NotNil(t, err)
	assert.True(t, called)
}

func TestRequestBadAttestationSignature(t *testing.T) {
	r, cfg := setup(t)

	s := NewService(cfg)

	fr := &FactRequest{
		SelfID: "1234567890",
		Expiry: time.Millisecond,
		Facts: []Fact{
			{
				Fact:    FactGivenNames,
				Sources: []string{SourceDrivingLicense},
			},
			{
				Fact:    FactSurname,
				Sources: []string{SourceDrivingLicense},
			},
		},
	}

	ipk, isk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	_, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	apk, _, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	r.addpk("1234567890", isk, ipk)
	r.addpk("test-attester", ask, apk)
	r.path = "/v1/identities/1234567890/devices"
	r.payload = []byte(`["1", "2"]`)
	r.secondaryPaths["/v1/apps/test"] = []byte(`{"paid_actions":true}`)

	var called bool

	r.responder = func(recipients []string, req []byte) (string, []byte, error) {
		called = true

		jws, err := jose.ParseSigned(string(req))
		require.Nil(t, err)

		payload, err := jws.Verify(s.sk.Public())
		require.Nil(t, err)

		var m standardresponse
		err = json.Unmarshal(payload, &m)
		require.Nil(t, err)

		assert.NotEmpty(t, m.ID)
		assert.NotEmpty(t, m.Conversation)
		assert.NotZero(t, m.IssuedAt)
		assert.NotZero(t, m.ExpiresAt)
		assert.Equal(t, RequestInformation, m.Type)
		assert.Equal(t, "test", m.Issuer)
		assert.Equal(t, fr.SelfID, m.Subject)
		assert.Equal(t, fr.SelfID, m.Audience)
		assert.Equal(t, fr.Description, m.Description)
		require.Len(t, m.Facts, 2)
		assert.Equal(t, FactGivenNames, m.Facts[0].Fact)
		assert.Equal(t, []string{SourceDrivingLicense}, m.Facts[0].Sources)
		assert.Equal(t, FactSurname, m.Facts[1].Fact)
		assert.Equal(t, []string{SourceDrivingLicense}, m.Facts[1].Sources)

		m.Type = ResponseInformation
		m.Issuer = fr.SelfID
		m.Subject = fr.SelfID
		m.Audience = "test"
		m.IssuedAt = ntp.TimeFunc()
		m.ExpiresAt = ntp.TimeFunc().Add(time.Minute)
		m.Status = "accepted"

		at, err := json.Marshal(map[string]string{
			"jti":         uuid.New().String(),
			"sub":         fr.SelfID,
			"iss":         "test-attester",
			"iat":         ntp.TimeFunc().Format(time.RFC3339),
			"source":      SourceDrivingLicense,
			"given_names": "pontiac",
		})

		opts := &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": "1",
			},
		}

		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: ask}, opts)
		require.Nil(t, err)

		attestation, err := s.Sign(at)
		require.Nil(t, err)

		m.Facts[0].Attestations = append(m.Facts[0].Attestations, []byte(attestation.FullSerialize()))

		at, err = json.Marshal(map[string]string{
			"jti":     uuid.New().String(),
			"sub":     fr.SelfID,
			"iss":     "test-attester",
			"iat":     ntp.TimeFunc().Format(time.RFC3339),
			"source":  SourceDrivingLicense,
			"surname": "bandit",
		})

		s, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: ask}, opts)
		require.Nil(t, err)

		attestation, err = s.Sign(at)
		require.Nil(t, err)

		m.Facts[1].Attestations = append(m.Facts[1].Attestations, []byte(attestation.FullSerialize()))

		resp, err := json.Marshal(m)
		require.Nil(t, err)

		s, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: isk}, opts)
		require.Nil(t, err)

		response, err := s.Sign(resp)
		require.Nil(t, err)

		return fr.SelfID + ":1", []byte(response.FullSerialize()), nil
	}

	_, err = s.Request(fr)
	require.NotNil(t, err)
	assert.True(t, called)
}

func TestRequestBadSignature(t *testing.T) {
	r, cfg := setup(t)

	s := NewService(cfg)

	fr := &FactRequest{
		SelfID: "1234567890",
		Expiry: time.Millisecond,
		Facts: []Fact{
			{
				Fact:    FactGivenNames,
				Sources: []string{SourceDrivingLicense},
			},
			{
				Fact:    FactSurname,
				Sources: []string{SourceDrivingLicense},
			},
		},
	}

	_, isk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	ipk, _, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	apk, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	r.addpk("1234567890", isk, ipk)
	r.addpk("test-attester", ask, apk)
	r.path = "/v1/identities/1234567890/devices"
	r.payload = []byte(`["1", "2"]`)
	r.secondaryPaths["/v1/apps/test"] = []byte(`{"paid_actions":true}`)

	var called bool

	r.responder = func(recipients []string, req []byte) (string, []byte, error) {
		called = true

		jws, err := jose.ParseSigned(string(req))
		require.Nil(t, err)

		payload, err := jws.Verify(s.sk.Public())
		require.Nil(t, err)

		var m standardresponse
		err = json.Unmarshal(payload, &m)
		require.Nil(t, err)

		assert.NotEmpty(t, m.ID)
		assert.NotEmpty(t, m.Conversation)
		assert.NotZero(t, m.IssuedAt)
		assert.NotZero(t, m.ExpiresAt)
		assert.Equal(t, RequestInformation, m.Type)
		assert.Equal(t, "test", m.Issuer)
		assert.Equal(t, fr.SelfID, m.Subject)
		assert.Equal(t, fr.SelfID, m.Audience)
		assert.Equal(t, fr.Description, m.Description)
		require.Len(t, m.Facts, 2)
		assert.Equal(t, FactGivenNames, m.Facts[0].Fact)
		assert.Equal(t, []string{SourceDrivingLicense}, m.Facts[0].Sources)
		assert.Equal(t, FactSurname, m.Facts[1].Fact)
		assert.Equal(t, []string{SourceDrivingLicense}, m.Facts[1].Sources)

		m.Type = ResponseInformation
		m.Issuer = fr.SelfID
		m.Subject = fr.SelfID
		m.Audience = "test"
		m.IssuedAt = ntp.TimeFunc()
		m.ExpiresAt = ntp.TimeFunc().Add(time.Minute)
		m.Status = "accepted"

		at, err := json.Marshal(map[string]string{
			"jti":         uuid.New().String(),
			"sub":         fr.SelfID,
			"iss":         "test-attester",
			"iat":         ntp.TimeFunc().Format(time.RFC3339),
			"source":      SourceDrivingLicense,
			"given_names": "pontiac",
		})

		opts := &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": "1",
			},
		}

		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: ask}, opts)
		require.Nil(t, err)

		attestation, err := s.Sign(at)
		require.Nil(t, err)

		m.Facts[0].Attestations = append(m.Facts[0].Attestations, []byte(attestation.FullSerialize()))

		at, err = json.Marshal(map[string]string{
			"jti":     uuid.New().String(),
			"sub":     fr.SelfID,
			"iss":     "test-attester",
			"iat":     ntp.TimeFunc().Format(time.RFC3339),
			"source":  SourceDrivingLicense,
			"surname": "bandit",
		})

		s, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: ask}, opts)
		require.Nil(t, err)

		attestation, err = s.Sign(at)
		require.Nil(t, err)

		m.Facts[1].Attestations = append(m.Facts[1].Attestations, []byte(attestation.FullSerialize()))

		resp, err := json.Marshal(m)
		require.Nil(t, err)

		s, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: isk}, opts)
		require.Nil(t, err)

		response, err := s.Sign(resp)
		require.Nil(t, err)

		return fr.SelfID + ":1", []byte(response.FullSerialize()), nil
	}

	_, err = s.Request(fr)
	require.NotNil(t, err)
	assert.True(t, called)
}

func TestRequestBadResponder(t *testing.T) {
	r, cfg := setup(t)

	s := NewService(cfg)

	fr := &FactRequest{
		SelfID: "1234567890",
		Expiry: time.Millisecond,
		Facts: []Fact{
			{
				Fact:    FactGivenNames,
				Sources: []string{SourceDrivingLicense},
			},
			{
				Fact:    FactSurname,
				Sources: []string{SourceDrivingLicense},
			},
		},
	}

	ipk, isk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	apk, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	r.addpk("1234567890", isk, ipk)
	r.addpk("test-attester", ask, apk)
	r.path = "/v1/identities/1234567890/devices"
	r.payload = []byte(`["1", "2"]`)
	r.secondaryPaths["/v1/apps/test"] = []byte(`{"paid_actions":true}`)

	var called bool

	r.responder = func(recipients []string, req []byte) (string, []byte, error) {
		called = true

		jws, err := jose.ParseSigned(string(req))
		require.Nil(t, err)

		payload, err := jws.Verify(s.sk.Public())
		require.Nil(t, err)

		var m standardresponse
		err = json.Unmarshal(payload, &m)
		require.Nil(t, err)

		assert.NotEmpty(t, m.ID)
		assert.NotEmpty(t, m.Conversation)
		assert.NotZero(t, m.IssuedAt)
		assert.NotZero(t, m.ExpiresAt)
		assert.Equal(t, RequestInformation, m.Type)
		assert.Equal(t, "test", m.Issuer)
		assert.Equal(t, fr.SelfID, m.Subject)
		assert.Equal(t, fr.SelfID, m.Audience)
		assert.Equal(t, fr.Description, m.Description)
		require.Len(t, m.Facts, 2)
		assert.Equal(t, FactGivenNames, m.Facts[0].Fact)
		assert.Equal(t, []string{SourceDrivingLicense}, m.Facts[0].Sources)
		assert.Equal(t, FactSurname, m.Facts[1].Fact)
		assert.Equal(t, []string{SourceDrivingLicense}, m.Facts[1].Sources)

		m.Type = ResponseInformation
		m.Issuer = fr.SelfID
		m.Subject = fr.SelfID
		m.Audience = "test"
		m.IssuedAt = ntp.TimeFunc()
		m.ExpiresAt = ntp.TimeFunc().Add(time.Minute)
		m.Status = "accepted"

		at, err := json.Marshal(map[string]string{
			"jti":         uuid.New().String(),
			"sub":         fr.SelfID,
			"iss":         "test-attester",
			"iat":         ntp.TimeFunc().Format(time.RFC3339),
			"source":      SourceDrivingLicense,
			"given_names": "pontiac",
		})

		opts := &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": "1",
			},
		}

		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: ask}, opts)
		require.Nil(t, err)

		attestation, err := s.Sign(at)
		require.Nil(t, err)

		m.Facts[0].Attestations = append(m.Facts[0].Attestations, []byte(attestation.FullSerialize()))

		at, err = json.Marshal(map[string]string{
			"jti":     uuid.New().String(),
			"sub":     fr.SelfID,
			"iss":     "test-attester",
			"iat":     ntp.TimeFunc().Format(time.RFC3339),
			"source":  SourceDrivingLicense,
			"surname": "bandit",
		})

		s, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: ask}, opts)
		require.Nil(t, err)

		attestation, err = s.Sign(at)
		require.Nil(t, err)

		m.Facts[1].Attestations = append(m.Facts[1].Attestations, []byte(attestation.FullSerialize()))

		resp, err := json.Marshal(m)
		require.Nil(t, err)

		s, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: isk}, opts)
		require.Nil(t, err)

		response, err := s.Sign(resp)
		require.Nil(t, err)

		return "bad:1", []byte(response.FullSerialize()), nil
	}

	_, err = s.Request(fr)
	require.NotNil(t, err)
	assert.True(t, called)
}

func TestRequestBadIssuingIdentity(t *testing.T) {
	r, cfg := setup(t)

	s := NewService(cfg)

	fr := &FactRequest{
		SelfID: "1234567890",
		Expiry: time.Millisecond,
		Facts: []Fact{
			{
				Fact:    FactGivenNames,
				Sources: []string{SourceDrivingLicense},
			},
			{
				Fact:    FactSurname,
				Sources: []string{SourceDrivingLicense},
			},
		},
	}

	ipk, isk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	apk, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	r.addpk("1234567890", isk, ipk)
	r.addpk("test-attester", ask, apk)
	r.path = "/v1/identities/1234567890/devices"
	r.payload = []byte(`["1", "2"]`)
	r.secondaryPaths["/v1/apps/test"] = []byte(`{"paid_actions":true}`)

	var called bool

	r.responder = func(recipients []string, req []byte) (string, []byte, error) {
		called = true

		jws, err := jose.ParseSigned(string(req))
		require.Nil(t, err)

		payload, err := jws.Verify(s.sk.Public())
		require.Nil(t, err)

		var m standardresponse
		err = json.Unmarshal(payload, &m)
		require.Nil(t, err)

		assert.NotEmpty(t, m.ID)
		assert.NotEmpty(t, m.Conversation)
		assert.NotZero(t, m.IssuedAt)
		assert.NotZero(t, m.ExpiresAt)
		assert.Equal(t, RequestInformation, m.Type)
		assert.Equal(t, "test", m.Issuer)
		assert.Equal(t, fr.SelfID, m.Subject)
		assert.Equal(t, fr.SelfID, m.Audience)
		assert.Equal(t, fr.Description, m.Description)
		require.Len(t, m.Facts, 2)
		assert.Equal(t, FactGivenNames, m.Facts[0].Fact)
		assert.Equal(t, []string{SourceDrivingLicense}, m.Facts[0].Sources)
		assert.Equal(t, FactSurname, m.Facts[1].Fact)
		assert.Equal(t, []string{SourceDrivingLicense}, m.Facts[1].Sources)

		m.Type = ResponseInformation
		m.Issuer = "bad"
		m.Subject = "bad"
		m.Audience = "test"
		m.IssuedAt = ntp.TimeFunc()
		m.ExpiresAt = ntp.TimeFunc().Add(time.Minute)
		m.Status = "accepted"

		at, err := json.Marshal(map[string]string{
			"jti":         uuid.New().String(),
			"sub":         fr.SelfID,
			"iss":         "test-attester",
			"iat":         ntp.TimeFunc().Format(time.RFC3339),
			"source":      SourceDrivingLicense,
			"given_names": "pontiac",
		})

		opts := &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": "1",
			},
		}

		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: ask}, opts)
		require.Nil(t, err)

		attestation, err := s.Sign(at)
		require.Nil(t, err)

		m.Facts[0].Attestations = append(m.Facts[0].Attestations, []byte(attestation.FullSerialize()))

		at, err = json.Marshal(map[string]string{
			"jti":     uuid.New().String(),
			"sub":     fr.SelfID,
			"iss":     "test-attester",
			"iat":     ntp.TimeFunc().Format(time.RFC3339),
			"source":  SourceDrivingLicense,
			"surname": "bandit",
		})

		s, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: ask}, opts)
		require.Nil(t, err)

		attestation, err = s.Sign(at)
		require.Nil(t, err)

		m.Facts[1].Attestations = append(m.Facts[1].Attestations, []byte(attestation.FullSerialize()))

		resp, err := json.Marshal(m)
		require.Nil(t, err)

		s, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: isk}, opts)
		require.Nil(t, err)

		response, err := s.Sign(resp)
		require.Nil(t, err)

		return fr.SelfID + ":1", []byte(response.FullSerialize()), nil
	}

	_, err = s.Request(fr)
	require.NotNil(t, err)
	assert.True(t, called)
}

func TestRequestBadAudienceIdentity(t *testing.T) {
	r, cfg := setup(t)

	s := NewService(cfg)

	fr := &FactRequest{
		SelfID: "1234567890",
		Expiry: time.Millisecond,
		Facts: []Fact{
			{
				Fact:    FactGivenNames,
				Sources: []string{SourceDrivingLicense},
			},
			{
				Fact:    FactSurname,
				Sources: []string{SourceDrivingLicense},
			},
		},
	}

	ipk, isk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	apk, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	r.addpk("1234567890", isk, ipk)
	r.addpk("test-attester", ask, apk)
	r.path = "/v1/identities/1234567890/devices"
	r.payload = []byte(`["1", "2"]`)
	r.secondaryPaths["/v1/apps/test"] = []byte(`{"paid_actions":true}`)

	var called bool

	r.responder = func(recipients []string, req []byte) (string, []byte, error) {
		called = true

		jws, err := jose.ParseSigned(string(req))
		require.Nil(t, err)

		payload, err := jws.Verify(s.sk.Public())
		require.Nil(t, err)

		var m standardresponse
		err = json.Unmarshal(payload, &m)
		require.Nil(t, err)

		assert.NotEmpty(t, m.ID)
		assert.NotEmpty(t, m.Conversation)
		assert.NotZero(t, m.IssuedAt)
		assert.NotZero(t, m.ExpiresAt)
		assert.Equal(t, RequestInformation, m.Type)
		assert.Equal(t, "test", m.Issuer)
		assert.Equal(t, fr.SelfID, m.Subject)
		assert.Equal(t, fr.SelfID, m.Audience)
		assert.Equal(t, fr.Description, m.Description)
		require.Len(t, m.Facts, 2)
		assert.Equal(t, FactGivenNames, m.Facts[0].Fact)
		assert.Equal(t, []string{SourceDrivingLicense}, m.Facts[0].Sources)
		assert.Equal(t, FactSurname, m.Facts[1].Fact)
		assert.Equal(t, []string{SourceDrivingLicense}, m.Facts[1].Sources)

		m.Type = ResponseInformation
		m.Issuer = fr.SelfID
		m.Subject = fr.SelfID
		m.Audience = "bad"
		m.IssuedAt = ntp.TimeFunc()
		m.ExpiresAt = ntp.TimeFunc().Add(time.Minute)
		m.Status = "accepted"

		at, err := json.Marshal(map[string]string{
			"jti":         uuid.New().String(),
			"sub":         fr.SelfID,
			"iss":         "test-attester",
			"iat":         ntp.TimeFunc().Format(time.RFC3339),
			"source":      SourceDrivingLicense,
			"given_names": "pontiac",
		})

		opts := &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": "1",
			},
		}

		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: ask}, opts)
		require.Nil(t, err)

		attestation, err := s.Sign(at)
		require.Nil(t, err)

		m.Facts[0].Attestations = append(m.Facts[0].Attestations, []byte(attestation.FullSerialize()))

		at, err = json.Marshal(map[string]string{
			"jti":     uuid.New().String(),
			"sub":     fr.SelfID,
			"iss":     "test-attester",
			"iat":     ntp.TimeFunc().Format(time.RFC3339),
			"source":  SourceDrivingLicense,
			"surname": "bandit",
		})

		s, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: ask}, opts)
		require.Nil(t, err)

		attestation, err = s.Sign(at)
		require.Nil(t, err)

		m.Facts[1].Attestations = append(m.Facts[1].Attestations, []byte(attestation.FullSerialize()))

		resp, err := json.Marshal(m)
		require.Nil(t, err)

		s, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: isk}, opts)
		require.Nil(t, err)

		response, err := s.Sign(resp)
		require.Nil(t, err)

		return fr.SelfID + ":1", []byte(response.FullSerialize()), nil
	}

	_, err = s.Request(fr)
	require.NotNil(t, err)
	assert.True(t, called)
}

func TestRequestResponseExpired(t *testing.T) {
	r, cfg := setup(t)

	s := NewService(cfg)

	fr := &FactRequest{
		SelfID: "1234567890",
		Expiry: time.Millisecond,
		Facts: []Fact{
			{
				Fact:    FactGivenNames,
				Sources: []string{SourceDrivingLicense},
			},
			{
				Fact:    FactSurname,
				Sources: []string{SourceDrivingLicense},
			},
		},
	}

	ipk, isk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	apk, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	r.addpk("1234567890", isk, ipk)
	r.addpk("test-attester", ask, apk)
	r.path = "/v1/identities/1234567890/devices"
	r.payload = []byte(`["1", "2"]`)
	r.secondaryPaths["/v1/apps/test"] = []byte(`{"paid_actions":true}`)

	var called bool

	r.responder = func(recipients []string, req []byte) (string, []byte, error) {
		called = true

		jws, err := jose.ParseSigned(string(req))
		require.Nil(t, err)

		payload, err := jws.Verify(s.sk.Public())
		require.Nil(t, err)

		var m standardresponse
		err = json.Unmarshal(payload, &m)
		require.Nil(t, err)

		assert.NotEmpty(t, m.ID)
		assert.NotEmpty(t, m.Conversation)
		assert.NotZero(t, m.IssuedAt)
		assert.NotZero(t, m.ExpiresAt)
		assert.Equal(t, RequestInformation, m.Type)
		assert.Equal(t, "test", m.Issuer)
		assert.Equal(t, fr.SelfID, m.Subject)
		assert.Equal(t, fr.SelfID, m.Audience)
		assert.Equal(t, fr.Description, m.Description)
		require.Len(t, m.Facts, 2)
		assert.Equal(t, FactGivenNames, m.Facts[0].Fact)
		assert.Equal(t, []string{SourceDrivingLicense}, m.Facts[0].Sources)
		assert.Equal(t, FactSurname, m.Facts[1].Fact)
		assert.Equal(t, []string{SourceDrivingLicense}, m.Facts[1].Sources)

		m.Type = ResponseInformation
		m.Issuer = fr.SelfID
		m.Subject = fr.SelfID
		m.Audience = "test"
		m.IssuedAt = ntp.TimeFunc().Add(-time.Hour)
		m.ExpiresAt = ntp.TimeFunc().Add(-time.Minute)
		m.Status = "accepted"

		at, err := json.Marshal(map[string]string{
			"jti":         uuid.New().String(),
			"sub":         fr.SelfID,
			"iss":         "test-attester",
			"iat":         ntp.TimeFunc().Format(time.RFC3339),
			"source":      SourceDrivingLicense,
			"given_names": "pontiac",
		})

		opts := &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": "1",
			},
		}

		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: ask}, opts)
		require.Nil(t, err)

		attestation, err := s.Sign(at)
		require.Nil(t, err)

		m.Facts[0].Attestations = append(m.Facts[0].Attestations, []byte(attestation.FullSerialize()))

		at, err = json.Marshal(map[string]string{
			"jti":     uuid.New().String(),
			"sub":     fr.SelfID,
			"iss":     "test-attester",
			"iat":     ntp.TimeFunc().Format(time.RFC3339),
			"source":  SourceDrivingLicense,
			"surname": "bandit",
		})

		s, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: ask}, opts)
		require.Nil(t, err)

		attestation, err = s.Sign(at)
		require.Nil(t, err)

		m.Facts[1].Attestations = append(m.Facts[1].Attestations, []byte(attestation.FullSerialize()))

		resp, err := json.Marshal(m)
		require.Nil(t, err)

		s, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: isk}, opts)
		require.Nil(t, err)

		response, err := s.Sign(resp)
		require.Nil(t, err)

		return fr.SelfID + ":1", []byte(response.FullSerialize()), nil
	}

	_, err = s.Request(fr)
	require.NotNil(t, err)
	assert.True(t, called)
}

func TestRequestResponseIssuedInFuture(t *testing.T) {
	r, cfg := setup(t)

	s := NewService(cfg)

	fr := &FactRequest{
		SelfID: "1234567890",
		Expiry: time.Millisecond,
		Facts: []Fact{
			{
				Fact:    FactGivenNames,
				Sources: []string{SourceDrivingLicense},
			},
			{
				Fact:    FactSurname,
				Sources: []string{SourceDrivingLicense},
			},
		},
	}

	ipk, isk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	apk, ask, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	r.addpk("1234567890", isk, ipk)
	r.addpk("test-attester", ask, apk)
	r.path = "/v1/identities/1234567890/devices"
	r.payload = []byte(`["1", "2"]`)
	r.secondaryPaths["/v1/apps/test"] = []byte(`{"paid_actions":true}`)

	var called bool

	r.responder = func(recipients []string, req []byte) (string, []byte, error) {
		called = true

		jws, err := jose.ParseSigned(string(req))
		require.Nil(t, err)

		payload, err := jws.Verify(s.sk.Public())
		require.Nil(t, err)

		var m standardresponse
		err = json.Unmarshal(payload, &m)
		require.Nil(t, err)

		assert.NotEmpty(t, m.ID)
		assert.NotEmpty(t, m.Conversation)
		assert.NotZero(t, m.IssuedAt)
		assert.NotZero(t, m.ExpiresAt)
		assert.Equal(t, RequestInformation, m.Type)
		assert.Equal(t, "test", m.Issuer)
		assert.Equal(t, fr.SelfID, m.Subject)
		assert.Equal(t, fr.SelfID, m.Audience)
		assert.Equal(t, fr.Description, m.Description)
		require.Len(t, m.Facts, 2)
		assert.Equal(t, FactGivenNames, m.Facts[0].Fact)
		assert.Equal(t, []string{SourceDrivingLicense}, m.Facts[0].Sources)
		assert.Equal(t, FactSurname, m.Facts[1].Fact)
		assert.Equal(t, []string{SourceDrivingLicense}, m.Facts[1].Sources)

		m.Type = ResponseInformation
		m.Issuer = fr.SelfID
		m.Subject = fr.SelfID
		m.Audience = "test"
		m.IssuedAt = ntp.TimeFunc().Add(time.Minute * 5)
		m.ExpiresAt = ntp.TimeFunc().Add(time.Minute * 10)
		m.Status = "accepted"

		at, err := json.Marshal(map[string]string{
			"jti":         uuid.New().String(),
			"sub":         fr.SelfID,
			"iss":         "test-attester",
			"iat":         ntp.TimeFunc().Format(time.RFC3339),
			"source":      SourceDrivingLicense,
			"given_names": "pontiac",
		})

		opts := &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": "1",
			},
		}

		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: ask}, opts)
		require.Nil(t, err)

		attestation, err := s.Sign(at)
		require.Nil(t, err)

		m.Facts[0].Attestations = append(m.Facts[0].Attestations, []byte(attestation.FullSerialize()))

		at, err = json.Marshal(map[string]string{
			"jti":     uuid.New().String(),
			"sub":     fr.SelfID,
			"iss":     "test-attester",
			"iat":     ntp.TimeFunc().Format(time.RFC3339),
			"source":  SourceDrivingLicense,
			"surname": "bandit",
		})

		s, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: ask}, opts)
		require.Nil(t, err)

		attestation, err = s.Sign(at)
		require.Nil(t, err)

		m.Facts[1].Attestations = append(m.Facts[1].Attestations, []byte(attestation.FullSerialize()))

		resp, err := json.Marshal(m)
		require.Nil(t, err)

		s, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: isk}, opts)
		require.Nil(t, err)

		response, err := s.Sign(resp)
		require.Nil(t, err)

		return fr.SelfID + ":1", []byte(response.FullSerialize()), nil
	}

	_, err = s.Request(fr)
	require.NotNil(t, err)
	assert.True(t, called)
}

func TestRequestViaIntermediary(t *testing.T) {
	r, cfg := setup(t)

	s := NewService(cfg)

	fr := &IntermediaryFactRequest{
		SelfID:       "1234567890",
		Intermediary: "intermediary",
		Expiry:       time.Millisecond,
		Facts: []Fact{
			{
				Fact:          FactDateOfBirth,
				Sources:       []string{SourceDrivingLicense, SourcePassport},
				Operator:      "<=",
				ExpectedValue: time.Now().Add(time.Hour * 183960).Format(time.RFC3339),
			},
		},
	}

	ipk, isk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	r.addpk("intermediary", isk, ipk)
	r.path = "/v1/apps/intermediary/devices"
	r.payload = []byte(`["1", "2"]`)
	r.secondaryPaths["/v1/apps/test"] = []byte(`{"paid_actions":true}`)

	var called bool

	r.responder = func(recipients []string, req []byte) (string, []byte, error) {
		called = true

		opts := &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": "1",
			},
		}

		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: isk}, opts)
		require.Nil(t, err)

		jws, err := jose.ParseSigned(string(req))
		require.Nil(t, err)

		payload, err := jws.Verify(s.sk.Public())
		require.Nil(t, err)

		var m standardresponse
		err = json.Unmarshal(payload, &m)
		require.Nil(t, err)

		assert.NotEmpty(t, m.ID)
		assert.NotEmpty(t, m.Conversation)
		assert.NotZero(t, m.IssuedAt)
		assert.NotZero(t, m.ExpiresAt)
		assert.Equal(t, RequestInformation, m.Type)
		assert.Equal(t, "test", m.Issuer)
		assert.Equal(t, fr.SelfID, m.Subject)
		assert.Equal(t, fr.Intermediary, m.Audience)
		assert.Equal(t, fr.Description, m.Description)
		require.Len(t, m.Facts, 1)
		assert.Equal(t, FactDateOfBirth, m.Facts[0].Fact)
		assert.Equal(t, []string{SourceDrivingLicense, SourcePassport}, m.Facts[0].Sources)
		assert.Equal(t, "<=", m.Facts[0].Operator)
		assert.Equal(t, fr.Facts[0].ExpectedValue, m.Facts[0].ExpectedValue)

		m.Type = ResponseInformation
		m.Issuer = fr.Intermediary
		m.Audience = "test"
		m.IssuedAt = ntp.TimeFunc()
		m.ExpiresAt = ntp.TimeFunc().Add(time.Minute)
		m.Status = "accepted"
		m.Facts = fr.Facts

		asrt, err := json.Marshal(map[string]interface{}{
			"jti":           uuid.New().String(),
			"sub":           "1234567890",
			"aud":           "test",
			"iss":           "intermediary",
			"iat":           ntp.TimeFunc().Format(time.RFC3339),
			FactDateOfBirth: true,
		})

		require.Nil(t, err)

		assertation, err := signer.Sign(asrt)
		require.Nil(t, err)

		m.Facts[0].Attestations = make([]json.RawMessage, 1)
		m.Facts[0].Attestations[0] = json.RawMessage(assertation.FullSerialize())

		resp, err := json.Marshal(m)
		require.Nil(t, err)

		response, err := signer.Sign(resp)
		require.Nil(t, err)

		return fr.Intermediary + ":1", []byte(response.FullSerialize()), nil
	}

	resp, err := s.RequestViaIntermediary(fr)
	require.Nil(t, err)
	assert.True(t, called)
	assert.Len(t, resp.Facts, 1)
	require.NotNil(t, resp.Facts[0].Result)
	assert.True(t, resp.Facts[0].Result())
	assert.Equal(t, []string{"intermediary:1", "intermediary:2"}, r.recipients)
}

func TestRequestViaIntermediaryTimeout(t *testing.T) {
	r, cfg := setup(t)

	s := NewService(cfg)

	fr := &IntermediaryFactRequest{
		SelfID:       "1234567890",
		Intermediary: "intermediary",
		Expiry:       time.Millisecond,
		Facts: []Fact{
			{
				Fact:          FactDateOfBirth,
				Sources:       []string{SourceDrivingLicense, SourcePassport},
				Operator:      "<=",
				ExpectedValue: time.Now().Add(time.Hour * 183960).Format(time.RFC3339),
			},
		},
	}

	ipk, isk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	r.addpk("intermediary", isk, ipk)
	r.path = "/v1/apps/intermediary/devices"
	r.payload = []byte(`["1", "2"]`)
	r.secondaryPaths["/v1/apps/test"] = []byte(`{"paid_actions":true}`)

	var called bool

	r.responder = func(recipients []string, req []byte) (string, []byte, error) {
		called = true
		return fr.Intermediary + ":1", nil, ErrRequestTimeout
	}

	_, err = s.RequestViaIntermediary(fr)
	require.NotNil(t, err)
	assert.True(t, called)
}

func TestRequestViaIntermediaryBadStatus(t *testing.T) {
	r, cfg := setup(t)

	s := NewService(cfg)

	fr := &IntermediaryFactRequest{
		SelfID:       "1234567890",
		Intermediary: "intermediary",
		Expiry:       time.Millisecond,
		Facts: []Fact{
			{
				Fact:          FactDateOfBirth,
				Sources:       []string{SourceDrivingLicense, SourcePassport},
				Operator:      "<=",
				ExpectedValue: time.Now().Add(time.Hour * 183960).Format(time.RFC3339),
			},
		},
	}

	ipk, isk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	r.addpk("intermediary", isk, ipk)
	r.path = "/v1/apps/intermediary/devices"
	r.payload = []byte(`["1", "2"]`)
	r.secondaryPaths["/v1/apps/test"] = []byte(`{"paid_actions":true}`)

	var called bool

	r.responder = func(recipients []string, req []byte) (string, []byte, error) {
		called = true

		jws, err := jose.ParseSigned(string(req))
		require.Nil(t, err)

		payload, err := jws.Verify(s.sk.Public())
		require.Nil(t, err)

		var m standardresponse
		err = json.Unmarshal(payload, &m)
		require.Nil(t, err)

		assert.NotEmpty(t, m.ID)
		assert.NotEmpty(t, m.Conversation)
		assert.NotZero(t, m.IssuedAt)
		assert.NotZero(t, m.ExpiresAt)
		assert.Equal(t, RequestInformation, m.Type)
		assert.Equal(t, "test", m.Issuer)
		assert.Equal(t, fr.SelfID, m.Subject)
		assert.Equal(t, fr.Intermediary, m.Audience)
		assert.Equal(t, fr.Description, m.Description)
		require.Len(t, m.Facts, 1)
		assert.Equal(t, FactDateOfBirth, m.Facts[0].Fact)
		assert.Equal(t, []string{SourceDrivingLicense, SourcePassport}, m.Facts[0].Sources)
		assert.Equal(t, "<=", m.Facts[0].Operator)
		assert.Equal(t, fr.Facts[0].ExpectedValue, m.Facts[0].ExpectedValue)

		m.Type = ResponseInformation
		m.Issuer = fr.Intermediary
		m.Audience = "test"
		m.IssuedAt = ntp.TimeFunc()
		m.ExpiresAt = ntp.TimeFunc().Add(time.Minute)
		m.Status = "rejected"

		resp, err := json.Marshal(m)
		require.Nil(t, err)

		opts := &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": "1",
			},
		}

		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: isk}, opts)
		require.Nil(t, err)

		response, err := signer.Sign(resp)
		require.Nil(t, err)

		return fr.Intermediary + ":1", []byte(response.FullSerialize()), nil
	}

	_, err = s.RequestViaIntermediary(fr)
	require.NotNil(t, err)
	assert.True(t, called)
}

func TestRequestViaIntermediaryBadSignature(t *testing.T) {
	r, cfg := setup(t)

	s := NewService(cfg)

	fr := &IntermediaryFactRequest{
		SelfID:       "1234567890",
		Intermediary: "intermediary",
		Expiry:       time.Millisecond,
		Facts: []Fact{
			{
				Fact:          FactDateOfBirth,
				Sources:       []string{SourceDrivingLicense, SourcePassport},
				Operator:      "<=",
				ExpectedValue: time.Now().Add(time.Hour * 183960).Format(time.RFC3339),
			},
		},
	}

	_, isk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	ipk, _, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	r.addpk("intermediary", isk, ipk)
	r.path = "/v1/apps/intermediary/devices"
	r.payload = []byte(`["1", "2"]`)
	r.secondaryPaths["/v1/apps/test"] = []byte(`{"paid_actions":true}`)

	var called bool

	r.responder = func(recipients []string, req []byte) (string, []byte, error) {
		called = true

		opts := &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": "1",
			},
		}

		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: isk}, opts)
		require.Nil(t, err)

		jws, err := jose.ParseSigned(string(req))
		require.Nil(t, err)

		payload, err := jws.Verify(s.sk.Public())
		require.Nil(t, err)

		var m standardresponse
		err = json.Unmarshal(payload, &m)
		require.Nil(t, err)

		assert.NotEmpty(t, m.ID)
		assert.NotEmpty(t, m.Conversation)
		assert.NotZero(t, m.IssuedAt)
		assert.NotZero(t, m.ExpiresAt)
		assert.Equal(t, RequestInformation, m.Type)
		assert.Equal(t, "test", m.Issuer)
		assert.Equal(t, fr.SelfID, m.Subject)
		assert.Equal(t, fr.Intermediary, m.Audience)
		assert.Equal(t, fr.Description, m.Description)
		require.Len(t, m.Facts, 1)
		assert.Equal(t, FactDateOfBirth, m.Facts[0].Fact)
		assert.Equal(t, []string{SourceDrivingLicense, SourcePassport}, m.Facts[0].Sources)
		assert.Equal(t, "<=", m.Facts[0].Operator)
		assert.Equal(t, fr.Facts[0].ExpectedValue, m.Facts[0].ExpectedValue)

		m.Type = ResponseInformation
		m.Issuer = fr.Intermediary
		m.Audience = "test"
		m.IssuedAt = ntp.TimeFunc()
		m.ExpiresAt = ntp.TimeFunc().Add(time.Minute)
		m.Status = "accepted"
		m.Facts = fr.Facts

		asrt, err := json.Marshal(map[string]interface{}{
			"jti":           uuid.New().String(),
			"sub":           "1234567890",
			"aud":           "test",
			"iss":           "intermediary",
			"iat":           ntp.TimeFunc().Format(time.RFC3339),
			FactDateOfBirth: true,
		})

		require.Nil(t, err)

		assertation, err := signer.Sign(asrt)
		require.Nil(t, err)

		m.Facts[0].Attestations = make([]json.RawMessage, 1)
		m.Facts[0].Attestations[0] = json.RawMessage(assertation.FullSerialize())

		resp, err := json.Marshal(m)
		require.Nil(t, err)

		response, err := signer.Sign(resp)
		require.Nil(t, err)

		return fr.Intermediary + ":1", []byte(response.FullSerialize()), nil
	}

	_, err = s.RequestViaIntermediary(fr)
	require.NotNil(t, err)
	assert.True(t, called)
}

func TestRequestViaIntermediaryBadResponder(t *testing.T) {
	r, cfg := setup(t)

	s := NewService(cfg)

	fr := &IntermediaryFactRequest{
		SelfID:       "1234567890",
		Intermediary: "intermediary",
		Expiry:       time.Millisecond,
		Facts: []Fact{
			{
				Fact:          FactDateOfBirth,
				Sources:       []string{SourceDrivingLicense, SourcePassport},
				Operator:      "<=",
				ExpectedValue: time.Now().Add(time.Hour * 183960).Format(time.RFC3339),
			},
		},
	}

	ipk, isk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	r.addpk("intermediary", isk, ipk)
	r.path = "/v1/apps/intermediary/devices"
	r.payload = []byte(`["1", "2"]`)
	r.secondaryPaths["/v1/apps/test"] = []byte(`{"paid_actions":true}`)

	var called bool

	r.responder = func(recipients []string, req []byte) (string, []byte, error) {
		called = true

		opts := &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": "1",
			},
		}

		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: isk}, opts)
		require.Nil(t, err)

		jws, err := jose.ParseSigned(string(req))
		require.Nil(t, err)

		payload, err := jws.Verify(s.sk.Public())
		require.Nil(t, err)

		var m standardresponse
		err = json.Unmarshal(payload, &m)
		require.Nil(t, err)

		assert.NotEmpty(t, m.ID)
		assert.NotEmpty(t, m.Conversation)
		assert.NotZero(t, m.IssuedAt)
		assert.NotZero(t, m.ExpiresAt)
		assert.Equal(t, RequestInformation, m.Type)
		assert.Equal(t, "test", m.Issuer)
		assert.Equal(t, fr.SelfID, m.Subject)
		assert.Equal(t, fr.Intermediary, m.Audience)
		assert.Equal(t, fr.Description, m.Description)
		require.Len(t, m.Facts, 1)
		assert.Equal(t, FactDateOfBirth, m.Facts[0].Fact)
		assert.Equal(t, []string{SourceDrivingLicense, SourcePassport}, m.Facts[0].Sources)
		assert.Equal(t, "<=", m.Facts[0].Operator)
		assert.Equal(t, fr.Facts[0].ExpectedValue, m.Facts[0].ExpectedValue)

		m.Type = ResponseInformation
		m.Issuer = fr.Intermediary
		m.Audience = "test"
		m.IssuedAt = ntp.TimeFunc()
		m.ExpiresAt = ntp.TimeFunc().Add(time.Minute)
		m.Status = "accepted"
		m.Facts = fr.Facts

		asrt, err := json.Marshal(map[string]interface{}{
			"jti":           uuid.New().String(),
			"sub":           "1234567890",
			"aud":           "test",
			"iss":           "intermediary",
			"iat":           ntp.TimeFunc().Format(time.RFC3339),
			FactDateOfBirth: true,
		})

		require.Nil(t, err)

		assertation, err := signer.Sign(asrt)
		require.Nil(t, err)

		m.Facts[0].Attestations = make([]json.RawMessage, 1)
		m.Facts[0].Attestations[0] = json.RawMessage(assertation.FullSerialize())

		resp, err := json.Marshal(m)
		require.Nil(t, err)

		response, err := signer.Sign(resp)
		require.Nil(t, err)

		return "bad:1", []byte(response.FullSerialize()), nil
	}

	_, err = s.RequestViaIntermediary(fr)
	require.NotNil(t, err)
	assert.True(t, called)
}

func TestRequestViaIntermediaryBadIssuingIdentity(t *testing.T) {
	r, cfg := setup(t)

	s := NewService(cfg)

	fr := &IntermediaryFactRequest{
		SelfID:       "1234567890",
		Intermediary: "intermediary",
		Expiry:       time.Millisecond,
		Facts: []Fact{
			{
				Fact:          FactDateOfBirth,
				Sources:       []string{SourceDrivingLicense, SourcePassport},
				Operator:      "<=",
				ExpectedValue: time.Now().Add(time.Hour * 183960).Format(time.RFC3339),
			},
		},
	}

	ipk, isk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	r.addpk("intermediary", isk, ipk)
	r.path = "/v1/apps/intermediary/devices"
	r.payload = []byte(`["1", "2"]`)
	r.secondaryPaths["/v1/apps/test"] = []byte(`{"paid_actions":true}`)

	var called bool

	r.responder = func(recipients []string, req []byte) (string, []byte, error) {
		called = true

		opts := &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": "1",
			},
		}

		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: isk}, opts)
		require.Nil(t, err)

		jws, err := jose.ParseSigned(string(req))
		require.Nil(t, err)

		payload, err := jws.Verify(s.sk.Public())
		require.Nil(t, err)

		var m standardresponse
		err = json.Unmarshal(payload, &m)
		require.Nil(t, err)

		assert.NotEmpty(t, m.ID)
		assert.NotEmpty(t, m.Conversation)
		assert.NotZero(t, m.IssuedAt)
		assert.NotZero(t, m.ExpiresAt)
		assert.Equal(t, RequestInformation, m.Type)
		assert.Equal(t, "test", m.Issuer)
		assert.Equal(t, fr.SelfID, m.Subject)
		assert.Equal(t, fr.Intermediary, m.Audience)
		assert.Equal(t, fr.Description, m.Description)
		require.Len(t, m.Facts, 1)
		assert.Equal(t, FactDateOfBirth, m.Facts[0].Fact)
		assert.Equal(t, []string{SourceDrivingLicense, SourcePassport}, m.Facts[0].Sources)
		assert.Equal(t, "<=", m.Facts[0].Operator)
		assert.Equal(t, fr.Facts[0].ExpectedValue, m.Facts[0].ExpectedValue)

		m.Type = ResponseInformation
		m.Issuer = "bad"
		m.Audience = "test"
		m.IssuedAt = ntp.TimeFunc()
		m.ExpiresAt = ntp.TimeFunc().Add(time.Minute)
		m.Status = "accepted"
		m.Facts = fr.Facts

		asrt, err := json.Marshal(map[string]interface{}{
			"jti":           uuid.New().String(),
			"sub":           "1234567890",
			"aud":           "test",
			"iss":           "bad",
			"iat":           ntp.TimeFunc().Format(time.RFC3339),
			FactDateOfBirth: true,
		})

		require.Nil(t, err)

		assertation, err := signer.Sign(asrt)
		require.Nil(t, err)

		m.Facts[0].Attestations = make([]json.RawMessage, 1)
		m.Facts[0].Attestations[0] = json.RawMessage(assertation.FullSerialize())

		resp, err := json.Marshal(m)
		require.Nil(t, err)

		response, err := signer.Sign(resp)
		require.Nil(t, err)

		return fr.Intermediary + ":1", []byte(response.FullSerialize()), nil
	}

	_, err = s.RequestViaIntermediary(fr)
	require.NotNil(t, err)
	assert.True(t, called)
}

func TestRequestViaIntermediaryBadAudienceIdentity(t *testing.T) {
	r, cfg := setup(t)

	s := NewService(cfg)

	fr := &IntermediaryFactRequest{
		SelfID:       "1234567890",
		Intermediary: "intermediary",
		Expiry:       time.Millisecond,
		Facts: []Fact{
			{
				Fact:          FactDateOfBirth,
				Sources:       []string{SourceDrivingLicense, SourcePassport},
				Operator:      "<=",
				ExpectedValue: time.Now().Add(time.Hour * 183960).Format(time.RFC3339),
			},
		},
	}

	ipk, isk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	r.addpk("intermediary", isk, ipk)
	r.path = "/v1/apps/intermediary/devices"
	r.payload = []byte(`["1", "2"]`)
	r.secondaryPaths["/v1/apps/test"] = []byte(`{"paid_actions":true}`)

	var called bool

	r.responder = func(recipients []string, req []byte) (string, []byte, error) {
		called = true

		opts := &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": "1",
			},
		}

		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: isk}, opts)
		require.Nil(t, err)

		jws, err := jose.ParseSigned(string(req))
		require.Nil(t, err)

		payload, err := jws.Verify(s.sk.Public())
		require.Nil(t, err)

		var m standardresponse
		err = json.Unmarshal(payload, &m)
		require.Nil(t, err)

		assert.NotEmpty(t, m.ID)
		assert.NotEmpty(t, m.Conversation)
		assert.NotZero(t, m.IssuedAt)
		assert.NotZero(t, m.ExpiresAt)
		assert.Equal(t, RequestInformation, m.Type)
		assert.Equal(t, "test", m.Issuer)
		assert.Equal(t, fr.SelfID, m.Subject)
		assert.Equal(t, fr.Intermediary, m.Audience)
		assert.Equal(t, fr.Description, m.Description)
		require.Len(t, m.Facts, 1)
		assert.Equal(t, FactDateOfBirth, m.Facts[0].Fact)
		assert.Equal(t, []string{SourceDrivingLicense, SourcePassport}, m.Facts[0].Sources)
		assert.Equal(t, "<=", m.Facts[0].Operator)
		assert.Equal(t, fr.Facts[0].ExpectedValue, m.Facts[0].ExpectedValue)

		m.Type = ResponseInformation
		m.Issuer = fr.Intermediary
		m.Audience = "bad"
		m.IssuedAt = ntp.TimeFunc()
		m.ExpiresAt = ntp.TimeFunc().Add(time.Minute)
		m.Status = "accepted"
		m.Facts = fr.Facts

		asrt, err := json.Marshal(map[string]interface{}{
			"jti":           uuid.New().String(),
			"sub":           "1234567890",
			"aud":           "bad",
			"iss":           "intermediary",
			"iat":           ntp.TimeFunc().Format(time.RFC3339),
			FactDateOfBirth: true,
		})

		require.Nil(t, err)

		assertation, err := signer.Sign(asrt)
		require.Nil(t, err)

		m.Facts[0].Attestations = make([]json.RawMessage, 1)
		m.Facts[0].Attestations[0] = json.RawMessage(assertation.FullSerialize())

		resp, err := json.Marshal(m)
		require.Nil(t, err)

		response, err := signer.Sign(resp)
		require.Nil(t, err)

		return fr.Intermediary + ":1", []byte(response.FullSerialize()), nil
	}

	_, err = s.RequestViaIntermediary(fr)
	require.NotNil(t, err)
	assert.True(t, called)
}

func TestRequestViaIntermediaryBadSubjectIdentity(t *testing.T) {
	r, cfg := setup(t)

	s := NewService(cfg)

	fr := &IntermediaryFactRequest{
		SelfID:       "1234567890",
		Intermediary: "intermediary",
		Expiry:       time.Millisecond,
		Facts: []Fact{
			{
				Fact:          FactDateOfBirth,
				Sources:       []string{SourceDrivingLicense, SourcePassport},
				Operator:      "<=",
				ExpectedValue: time.Now().Add(time.Hour * 183960).Format(time.RFC3339),
			},
		},
	}

	ipk, isk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	r.addpk("intermediary", isk, ipk)
	r.path = "/v1/apps/intermediary/devices"
	r.payload = []byte(`["1", "2"]`)
	r.secondaryPaths["/v1/apps/test"] = []byte(`{"paid_actions":true}`)

	var called bool

	r.responder = func(recipients []string, req []byte) (string, []byte, error) {
		called = true

		opts := &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": "1",
			},
		}

		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: isk}, opts)
		require.Nil(t, err)

		jws, err := jose.ParseSigned(string(req))
		require.Nil(t, err)

		payload, err := jws.Verify(s.sk.Public())
		require.Nil(t, err)

		var m standardresponse
		err = json.Unmarshal(payload, &m)
		require.Nil(t, err)

		assert.NotEmpty(t, m.ID)
		assert.NotEmpty(t, m.Conversation)
		assert.NotZero(t, m.IssuedAt)
		assert.NotZero(t, m.ExpiresAt)
		assert.Equal(t, RequestInformation, m.Type)
		assert.Equal(t, "test", m.Issuer)
		assert.Equal(t, fr.SelfID, m.Subject)
		assert.Equal(t, fr.Intermediary, m.Audience)
		assert.Equal(t, fr.Description, m.Description)
		require.Len(t, m.Facts, 1)
		assert.Equal(t, FactDateOfBirth, m.Facts[0].Fact)
		assert.Equal(t, []string{SourceDrivingLicense, SourcePassport}, m.Facts[0].Sources)
		assert.Equal(t, "<=", m.Facts[0].Operator)
		assert.Equal(t, fr.Facts[0].ExpectedValue, m.Facts[0].ExpectedValue)

		m.Type = ResponseInformation
		m.Issuer = fr.Intermediary
		m.Subject = "bad"
		m.Audience = "test"
		m.IssuedAt = ntp.TimeFunc()
		m.ExpiresAt = ntp.TimeFunc().Add(time.Minute)
		m.Status = "accepted"
		m.Facts = fr.Facts

		asrt, err := json.Marshal(map[string]interface{}{
			"jti":           uuid.New().String(),
			"sub":           "bad",
			"aud":           "test",
			"iss":           "intermediary",
			"iat":           ntp.TimeFunc().Format(time.RFC3339),
			FactDateOfBirth: true,
		})

		require.Nil(t, err)

		assertation, err := signer.Sign(asrt)
		require.Nil(t, err)

		m.Facts[0].Attestations = make([]json.RawMessage, 1)
		m.Facts[0].Attestations[0] = json.RawMessage(assertation.FullSerialize())

		resp, err := json.Marshal(m)
		require.Nil(t, err)

		response, err := signer.Sign(resp)
		require.Nil(t, err)

		return fr.Intermediary + ":1", []byte(response.FullSerialize()), nil
	}

	_, err = s.RequestViaIntermediary(fr)
	require.NotNil(t, err)
	assert.True(t, called)
}

func TestRequestViaIntermediaryResponseExpired(t *testing.T) {
	r, cfg := setup(t)

	s := NewService(cfg)

	fr := &IntermediaryFactRequest{
		SelfID:       "1234567890",
		Intermediary: "intermediary",
		Expiry:       time.Millisecond,
		Facts: []Fact{
			{
				Fact:          FactDateOfBirth,
				Sources:       []string{SourceDrivingLicense, SourcePassport},
				Operator:      "<=",
				ExpectedValue: time.Now().Add(time.Hour * 183960).Format(time.RFC3339),
			},
		},
	}

	ipk, isk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	r.addpk("intermediary", isk, ipk)
	r.path = "/v1/apps/intermediary/devices"
	r.payload = []byte(`["1", "2"]`)
	r.secondaryPaths["/v1/apps/test"] = []byte(`{"paid_actions":true}`)

	var called bool

	r.responder = func(recipients []string, req []byte) (string, []byte, error) {
		called = true

		opts := &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": "1",
			},
		}

		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: isk}, opts)
		require.Nil(t, err)

		jws, err := jose.ParseSigned(string(req))
		require.Nil(t, err)

		payload, err := jws.Verify(s.sk.Public())
		require.Nil(t, err)

		var m standardresponse
		err = json.Unmarshal(payload, &m)
		require.Nil(t, err)

		assert.NotEmpty(t, m.ID)
		assert.NotEmpty(t, m.Conversation)
		assert.NotZero(t, m.IssuedAt)
		assert.NotZero(t, m.ExpiresAt)
		assert.Equal(t, RequestInformation, m.Type)
		assert.Equal(t, "test", m.Issuer)
		assert.Equal(t, fr.SelfID, m.Subject)
		assert.Equal(t, fr.Intermediary, m.Audience)
		assert.Equal(t, fr.Description, m.Description)
		require.Len(t, m.Facts, 1)
		assert.Equal(t, FactDateOfBirth, m.Facts[0].Fact)
		assert.Equal(t, []string{SourceDrivingLicense, SourcePassport}, m.Facts[0].Sources)
		assert.Equal(t, "<=", m.Facts[0].Operator)
		assert.Equal(t, fr.Facts[0].ExpectedValue, m.Facts[0].ExpectedValue)

		m.Type = ResponseInformation
		m.Issuer = fr.Intermediary
		m.Audience = "test"
		m.IssuedAt = ntp.TimeFunc().Add(-time.Hour)
		m.ExpiresAt = ntp.TimeFunc().Add(-(time.Minute * 2))
		m.Status = "accepted"
		m.Facts = fr.Facts

		asrt, err := json.Marshal(map[string]interface{}{
			"jti":           uuid.New().String(),
			"sub":           "bad",
			"aud":           "test",
			"iss":           "intermediary",
			"iat":           ntp.TimeFunc().Add(-time.Hour).Format(time.RFC3339),
			FactDateOfBirth: true,
		})

		require.Nil(t, err)

		assertation, err := signer.Sign(asrt)
		require.Nil(t, err)

		m.Facts[0].Attestations = make([]json.RawMessage, 1)
		m.Facts[0].Attestations[0] = json.RawMessage(assertation.FullSerialize())

		resp, err := json.Marshal(m)
		require.Nil(t, err)

		response, err := signer.Sign(resp)
		require.Nil(t, err)

		return fr.Intermediary + ":1", []byte(response.FullSerialize()), nil
	}

	_, err = s.RequestViaIntermediary(fr)
	require.NotNil(t, err)
	assert.True(t, called)
}

func TestRequestViaIntermediaryResponseIssuedInFuture(t *testing.T) {
	r, cfg := setup(t)

	s := NewService(cfg)

	fr := &IntermediaryFactRequest{
		SelfID:       "1234567890",
		Intermediary: "intermediary",
		Expiry:       time.Millisecond,
		Facts: []Fact{
			{
				Fact:          FactDateOfBirth,
				Sources:       []string{SourceDrivingLicense, SourcePassport},
				Operator:      "<=",
				ExpectedValue: time.Now().Add(time.Hour * 183960).Format(time.RFC3339),
			},
		},
	}

	ipk, isk, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)

	r.addpk("intermediary", isk, ipk)
	r.path = "/v1/apps/intermediary/devices"
	r.payload = []byte(`["1", "2"]`)
	r.secondaryPaths["/v1/apps/test"] = []byte(`{"paid_actions":true}`)

	var called bool

	r.responder = func(recipients []string, req []byte) (string, []byte, error) {
		called = true

		opts := &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": "1",
			},
		}

		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: isk}, opts)
		require.Nil(t, err)

		jws, err := jose.ParseSigned(string(req))
		require.Nil(t, err)

		payload, err := jws.Verify(s.sk.Public())
		require.Nil(t, err)

		var m standardresponse
		err = json.Unmarshal(payload, &m)
		require.Nil(t, err)

		assert.NotEmpty(t, m.ID)
		assert.NotEmpty(t, m.Conversation)
		assert.NotZero(t, m.IssuedAt)
		assert.NotZero(t, m.ExpiresAt)
		assert.Equal(t, RequestInformation, m.Type)
		assert.Equal(t, "test", m.Issuer)
		assert.Equal(t, fr.SelfID, m.Subject)
		assert.Equal(t, fr.Intermediary, m.Audience)
		assert.Equal(t, fr.Description, m.Description)
		require.Len(t, m.Facts, 1)
		assert.Equal(t, FactDateOfBirth, m.Facts[0].Fact)
		assert.Equal(t, []string{SourceDrivingLicense, SourcePassport}, m.Facts[0].Sources)
		assert.Equal(t, "<=", m.Facts[0].Operator)
		assert.Equal(t, fr.Facts[0].ExpectedValue, m.Facts[0].ExpectedValue)

		m.Type = ResponseInformation
		m.Issuer = fr.Intermediary
		m.Subject = fr.Intermediary
		m.Audience = "test"
		m.IssuedAt = ntp.TimeFunc().Add(time.Hour)
		m.ExpiresAt = ntp.TimeFunc().Add(time.Hour * 2)
		m.Status = "accepted"
		m.Facts = fr.Facts

		asrt, err := json.Marshal(map[string]interface{}{
			"jti":           uuid.New().String(),
			"sub":           "bad",
			"aud":           "test",
			"iss":           "intermediary",
			"iat":           ntp.TimeFunc().Add(time.Hour).Format(time.RFC3339),
			FactDateOfBirth: true,
		})

		require.Nil(t, err)

		assertation, err := signer.Sign(asrt)
		require.Nil(t, err)

		m.Facts[0].Attestations = make([]json.RawMessage, 1)
		m.Facts[0].Attestations[0] = json.RawMessage(assertation.FullSerialize())

		resp, err := json.Marshal(m)
		require.Nil(t, err)

		response, err := signer.Sign(resp)
		require.Nil(t, err)

		return fr.Intermediary + ":1", []byte(response.FullSerialize()), nil
	}

	_, err = s.RequestViaIntermediary(fr)
	require.NotNil(t, err)
	assert.True(t, called)
}

func TestGenerateQRCode(t *testing.T) {

}

func TestWaitForResponse(t *testing.T) {

}
