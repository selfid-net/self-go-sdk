package messaging

import (
	"encoding/json"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/selfid-net/self-go-sdk/pkg/ntp"
	"github.com/square/go-jose"
	"github.com/tidwall/sjson"
)

var (
	ErrBadJSONPayload       = errors.New("bad json payload")
	ErrResponseBadSignature = errors.New("bad response signature")
	ErrRequestTimeout       = errors.New("request timeout")
	ErrMessageBadIssuer     = errors.New("bad response issuer")
	ErrMessageBadAudience   = errors.New("bad response audience")
	ErrMessageBadStatus     = errors.New("bad response status")
	ErrMessageExpired       = errors.New("response has expired")
	ErrMessageIssuedTooSoon = errors.New("response was issued in the future")
)

// Message message
type Message struct {
	Sender         string
	ConversationID string
	Payload        []byte
}

// infoNotification message
type infoNotification struct {
	ID           string    `json:"jti"`
	Type         string    `json:"typ"`
	Conversation string    `json:"cid"`
	Issuer       string    `json:"iss"`
	Audience     string    `json:"aud"`
	Subject      string    `json:"sub"`
	IssuedAt     time.Time `json:"iat"`
	ExpiresAt    time.Time `json:"exp"`
	Description  string    `json:"description"`
}

// Subscribe subscribe to messages of a given type
func (s *Service) Subscribe(messageType string, h func(m *Message)) {
	s.messaging.Subscribe(messageType, func(sender string, payload []byte) {
		selfID := strings.Split(sender, ":")[0]

		pks, err := s.pki.GetPublicKeys(selfID)
		if err != nil {
			log.Println("messaging: message does not originate from a valid self id")
			return
		}

		// TODO extract this into a reusable function

		var keys []publickey

		err = json.Unmarshal(pks, &keys)
		if err != nil {
			log.Println("messaging: could not find any valid public keys for sender")
			return
		}

		jws, err := jose.ParseSigned(string(payload))
		if err != nil {
			log.Println("messaging: message does not contain a valid jws")
			return
		}

		var verified bool
		var msg []byte

		for _, k := range keys {
			msg, err = jws.Verify(k.pk())
			if err == nil {
				verified = true
				break
			}
		}

		if !verified {
			log.Println("messaging: message does not have a valid signature")
			return
		}

		var mp jwsPayload

		err = json.Unmarshal(msg, &mp)
		if err != nil {
			log.Println("messaging: received a bad message payload")
			return
		}

		if mp.Audience != s.selfID {
			log.Println("messaging:", ErrMessageBadAudience.Error())
			return
		}

		if mp.Issuer != selfID {
			log.Println("messaging:", ErrMessageBadIssuer.Error())
			return
		}

		if ntp.TimeFunc().After(mp.ExpiresAt) {
			log.Println("messaging:", ErrMessageExpired.Error())
			return
		}

		if mp.IssuedAt.After(ntp.TimeFunc()) {
			log.Println("messaging:", ErrMessageIssuedTooSoon.Error())
			return
		}

		// verify jws's and send jws payload to subscription...
		h(&Message{sender, mp.Conversation, msg})
	})
}

func (s *Service) serializeRequest(request []byte, cid string) (string, error) {
	var err error

	request, err = sjson.SetBytes(request, "cid", cid)
	if err != nil {
		return "", err
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: s.sk}, nil)
	if err != nil {
		return "", err
	}

	signedRequest, err := signer.Sign(request)
	if err != nil {
		return "", err
	}

	return signedRequest.FullSerialize(), nil
}

// Request make a request to an identity
func (s *Service) Request(recipients []string, request []byte) ([]byte, error) {
	cid := uuid.New().String()

	plaintext, err := s.serializeRequest(request, cid)
	if err != nil {
		return nil, err
	}

	sender, response, err := s.messaging.Request(recipients, cid, []byte(plaintext))
	if err != nil {
		return nil, err
	}

	selfID := strings.Split(sender, ":")[0]

	pks, err := s.pki.GetPublicKeys(selfID)
	if err != nil {
		return nil, err
	}

	var keys []publickey

	err = json.Unmarshal(pks, &keys)
	if err != nil {
		return nil, err
	}

	jws, err := jose.ParseSigned(string(response))
	if err != nil {
		return nil, err
	}

	var verified bool
	var msg []byte

	for _, k := range keys {
		msg, err = jws.Verify(k.pk())
		if err == nil {
			verified = true
			break
		}
	}

	if !verified {
		return nil, ErrResponseBadSignature
	}

	var mp jwsPayload

	err = json.Unmarshal(msg, &mp)
	if err != nil {
		return nil, ErrBadJSONPayload
	}

	if mp.Audience != s.selfID {
		return nil, ErrMessageBadAudience
	}

	if mp.Issuer != selfID {
		return nil, ErrMessageBadIssuer
	}

	if ntp.TimeFunc().After(mp.ExpiresAt) {
		return nil, ErrMessageExpired
	}

	if mp.IssuedAt.After(ntp.TimeFunc()) {
		return nil, ErrMessageIssuedTooSoon
	}

	return msg, nil
}

// Respond sends a message to a given sender
func (s *Service) Respond(recipient, conversationID string, response []byte) error {
	return s.Send([]string{recipient}, conversationID, response)
}

// Send sends a message to the given recipient
func (s *Service) Send(recipients []string, conversationID string, body []byte) error {
	plaintext, err := s.serializeRequest(body, conversationID)
	if err != nil {
		return err
	}

	return s.messaging.Send(recipients, []byte(plaintext))
}

// Notify sends a notification to the given recipient
func (s *Service) Notify(recipient, body string) error {
	cid := uuid.New().String()
	req := infoNotification{
		ID:           uuid.New().String(),
		Conversation: cid,
		Type:         "identities.notify",
		Issuer:       s.selfID,
		Subject:      recipient,
		Audience:     recipient,
		IssuedAt:     ntp.TimeFunc(),
		ExpiresAt:    ntp.TimeFunc().Add(time.Hour * 24),
		Description:  body,
	}

	data, err := json.Marshal(req)
	if err != nil {
		log.Println(err)
		return err
	}

	return s.Send([]string{recipient}, cid, data)
}
