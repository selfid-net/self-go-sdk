package messaging

import (
	"encoding/json"
	"errors"
	"log"
	"strings"

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

// Request make a request to an identity
func (s *Service) Request(recipients []string, request []byte) ([]byte, error) {
	var err error

	cid := uuid.New().String()

	request, err = sjson.SetBytes(request, "cid", cid)
	if err != nil {
		return nil, err
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: s.sk}, nil)
	if err != nil {
		return nil, err
	}

	signedRequest, err := signer.Sign(request)
	if err != nil {
		return nil, err
	}

	plaintext := signedRequest.FullSerialize()

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
	var err error

	response, err = sjson.SetBytes(response, "cid", conversationID)
	if err != nil {
		return err
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: s.sk}, nil)
	if err != nil {
		return err
	}

	signedResponse, err := signer.Sign(response)
	if err != nil {
		return err
	}

	plaintext := signedResponse.FullSerialize()

	return s.messaging.Send([]string{recipient}, []byte(plaintext))
}

// Send sends a message to a given sender
func (s *Service) Send(recipient string, body []byte) error {
	cid := uuid.New().String()

	return s.Respond(recipient, cid, body)
}
