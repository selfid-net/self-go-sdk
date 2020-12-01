package messaging

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/joinself/self-go-sdk/pkg/ntp"
	"github.com/joinself/self-go-sdk/pkg/siggraph"
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

		jws, err := jose.ParseSigned(string(payload))
		if err != nil {
			log.Println("messaging: message does not contain a valid jws")
			return
		}

		history, err := s.pki.GetHistory(selfID)
		if err != nil {
			log.Println("messaging: ", err)
			return
		}

		sg, err := siggraph.New(history)
		if err != nil {
			log.Println("messaging: ", err)
			return
		}

		kid, err := getJWSKID(payload)
		if err != nil {
			log.Println("messaging: ", err)
			return
		}

		pk, err := sg.ActiveKey(kid)
		if err != nil {
			log.Println("messaging: ", err)
			return
		}

		msg, err := jws.Verify(pk)
		if err != nil {
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

		if mp.IssuedAt.Add(-time.Second * 5).After(ntp.TimeFunc()) {
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

	opts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": s.keyID,
		},
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: s.sk}, opts)
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

	sender, response, err := s.messaging.Request(recipients, cid, []byte(plaintext), 0)
	if err != nil {
		return nil, err
	}

	selfID := strings.Split(sender, ":")[0]

	jws, err := jose.ParseSigned(string(response))
	if err != nil {
		return nil, err
	}

	history, err := s.pki.GetHistory(selfID)
	if err != nil {
		return nil, err
	}

	sg, err := siggraph.New(history)
	if err != nil {
		return nil, err
	}

	kid, err := getJWSKID(response)
	if err != nil {
		return nil, err
	}

	pk, err := sg.ActiveKey(kid)
	if err != nil {
		return nil, err
	}

	msg, err := jws.Verify(pk)
	if err != nil {
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

// Notify sends a notification to a given self ID
func (s *Service) Notify(selfID, content string) error {
	cid := uuid.New().String()

	req := infoNotification{
		ID:           uuid.New().String(),
		Conversation: cid,
		Type:         "identities.notify",
		Issuer:       s.selfID,
		Subject:      selfID,
		Audience:     selfID,
		IssuedAt:     ntp.TimeFunc(),
		ExpiresAt:    ntp.TimeFunc().Add(time.Hour * 24),
		Description:  content,
	}

	data, err := json.Marshal(req)
	if err != nil {
		return err
	}

	recipients, err := s.recipients(selfID)
	if err != nil {
		return err
	}

	return s.Send(recipients, cid, data)
}

// builds a list of all devices associated with an identity
func (s *Service) recipients(selfID string) ([]string, error) {
	var resp []byte
	var err error

	if len(selfID) > 11 {
		resp, err = s.api.Get("/v1/apps/" + selfID + "/devices")
	} else {
		resp, err = s.api.Get("/v1/identities/" + selfID + "/devices")
	}

	if err != nil {
		return nil, err
	}

	var devices []string

	err = json.Unmarshal(resp, &devices)
	if err != nil {
		return nil, err
	}

	for i := range devices {
		devices[i] = selfID + ":" + devices[i]
	}

	return devices, nil
}

func getKID(token string) (string, error) {
	data, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	if err != nil {
		return "", err
	}

	hdr := make(map[string]string)

	err = json.Unmarshal(data, &hdr)
	if err != nil {
		return "", err
	}

	kid := hdr["kid"]
	if kid == "" {
		return "", errors.New("token must specify an identifier for the signing key")
	}

	return kid, nil
}

func getJWSKID(payload []byte) (string, error) {
	var jws struct {
		Protected string `json:"protected"`
	}

	err := json.Unmarshal(payload, &jws)
	if err != nil {
		return "", err
	}

	return getKID(jws.Protected)
}
