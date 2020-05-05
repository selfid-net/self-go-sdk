package fact

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/selfid-net/self-go-sdk/pkg/ntp"
	"github.com/google/uuid"
	"github.com/lucasb-eyer/go-colorful"
	"github.com/skip2/go-qrcode"
	"github.com/square/go-jose"
	"github.com/tidwall/gjson"
)

var (
	ErrBadJSONPayload               = errors.New("bad json payload")
	ErrResponseBadSignature         = errors.New("bad response signature")
	ErrRequestTimeout               = errors.New("request timeout")
	ErrMessageBadIssuer             = errors.New("bad response issuer")
	ErrMessageBadSubject            = errors.New("bad response subject")
	ErrMessageBadAudience           = errors.New("bad response audience")
	ErrMessageBadStatus             = errors.New("bad response status")
	ErrMessageExpired               = errors.New("response has expired")
	ErrMessageIssuedTooSoon         = errors.New("response was issued in the future")
	ErrStatusRejected               = errors.New("fact request was rejected")
	ErrStatusUnauthorized           = errors.New("you are not authorized to interact with this user")
	ErrFactRequestBadIdentity       = errors.New("fact request must specify a valid self id")
	ErrFactRequestBadFacts          = errors.New("fact request must specify one or more facts")
	ErrFactQRRequestBadConversation = errors.New("fact qr request must specify a valid conversation id")
	ErrFactQRRequestBadFacts        = errors.New("fact qr request must specify one or more facts")
	ErrFactResultMismatch           = errors.New("fact has differing attested values")
	ErrFactNotAttested              = errors.New("fact has attestations with empty or invalid values")
	ErrBadAttestationSubject        = errors.New("attestation is not related to the responder")

	ServiceSelfIntermediary = "self_intermediary"
)

// FactRequest specifies the parameters of an information request
type FactRequest struct {
	SelfID      string
	Description string
	Facts       []Fact
	Expiry      time.Duration
}

// FactResponse contains the details of the requested facts
type FactResponse struct {
	Facts []Fact
}

// QRFactRequest contains the details of the requested facts
type QRFactRequest struct {
	ConversationID string
	Description    string
	Facts          []Fact
	Expiry         time.Duration
	QRConfig       QRConfig
}

// QRFactResponse contains the details of the requested facts
type QRFactResponse struct {
	Responder string
	Facts     []Fact
}

type QRConfig struct {
	Size            int
	ForegroundColor string
	BackgroundColor string
}

// IntermediaryFactRequest specifies the paramters on an information request via an intermediary
type IntermediaryFactRequest struct {
	SelfID       string
	Description  string
	Intermediary string
	Facts        []Fact
	Expiry       time.Duration
}

// IntermediaryFactResponse contains the details of the requested facts
type IntermediaryFactResponse struct {
	Facts []Fact
}

type standardresponse struct {
	ID           string    `json:"jti"`
	Type         string    `json:"typ"`
	Conversation string    `json:"cid"`
	Issuer       string    `json:"iss"`
	Audience     string    `json:"aud"`
	Subject      string    `json:"sub"`
	IssuedAt     time.Time `json:"iat"`
	ExpiresAt    time.Time `json:"exp"`
	DeviceID     string    `json:"device_id"`
	Status       string    `json:"status"`
	Description  string    `json:"description"`
	Facts        []Fact    `json:"facts"`
}

// Request requests a fact from a given identity
func (s Service) Request(req *FactRequest) (*FactResponse, error) {
	if req.SelfID == "" {
		return nil, ErrFactRequestBadIdentity
	}

	if len(req.Facts) < 1 {
		return nil, ErrFactRequestBadFacts
	}

	if req.Expiry == 0 {
		req.Expiry = defaultRequestTimeout
	}

	cid := uuid.New().String()

	payload, err := s.factPayload(cid, req.SelfID, req.SelfID, req.Description, req.Facts, req.Expiry)
	if err != nil {
		return nil, err
	}

	recipients, err := s.recipients(req.SelfID)
	if err != nil {
		return nil, err
	}

	responder, response, err := s.messaging.Request(recipients, cid, payload)
	if err != nil {
		return nil, err
	}

	selfID := strings.Split(responder, ":")[0]

	if selfID != req.SelfID {
		return nil, ErrMessageBadIssuer
	}

	facts, err := s.factResponse(selfID, selfID, response)
	if err != nil {
		return nil, err
	}

	return &FactResponse{Facts: facts}, nil
}

// RequestViaIntermediary requests a fact from a given identity via a trusted
// intermediary. The intermediary verifies that the identity has a given fact
// and that it meets the requested requirements.
func (s Service) RequestViaIntermediary(req *IntermediaryFactRequest) (*IntermediaryFactResponse, error) {
	if req.Expiry == 0 {
		req.Expiry = defaultRequestTimeout
	}

	if req.Intermediary == "" {
		req.Intermediary = ServiceSelfIntermediary
	}

	cid := uuid.New().String()

	payload, err := s.factPayload(cid, req.SelfID, req.Intermediary, req.Description, req.Facts, req.Expiry)
	if err != nil {
		return nil, err
	}

	recipients, err := s.recipients(req.Intermediary)
	if err != nil {
		return nil, err
	}

	responder, response, err := s.messaging.Request(recipients, cid, payload)
	if err != nil {
		return nil, err
	}

	selfID := strings.Split(responder, ":")[0]

	if selfID != req.Intermediary {
		return nil, ErrMessageBadIssuer
	}

	resp, err := jose.ParseSigned(string(response))
	if err != nil {
		return nil, err
	}

	sub := gjson.GetBytes(resp.UnsafePayloadWithoutVerification(), "sub").String()

	if sub != req.SelfID {
		return nil, ErrMessageBadSubject
	}

	facts, err := s.factResponse(req.Intermediary, req.SelfID, response)
	if err != nil {
		return nil, err
	}

	return &IntermediaryFactResponse{Facts: facts}, nil
}

// GenerateFactQR generates a qr code containing an fact request
func (s Service) GenerateQRCode(req *QRFactRequest) ([]byte, error) {
	if req.ConversationID == "" {
		return nil, ErrFactQRRequestBadConversation
	}

	if req.Expiry == 0 {
		req.Expiry = defaultRequestTimeout
	}

	if req.QRConfig.ForegroundColor == "" {
		req.QRConfig.ForegroundColor = "#0E1C42"
	}

	if req.QRConfig.BackgroundColor == "" {
		req.QRConfig.BackgroundColor = "#FFFFFF"
	}

	if req.QRConfig.Size == 0 {
		req.QRConfig.Size = 400
	}

	payload, err := s.factPayload(req.ConversationID, "-", "-", req.Description, req.Facts, req.Expiry)
	if err != nil {
		return nil, err
	}

	q, err := qrcode.New(string(payload), qrcode.Low)
	if err != nil {
		return nil, err
	}

	q.BackgroundColor, _ = colorful.Hex(req.QRConfig.BackgroundColor)
	q.ForegroundColor, _ = colorful.Hex(req.QRConfig.ForegroundColor)

	s.messaging.Register(req.ConversationID)

	return q.PNG(req.QRConfig.Size)
}

// WaitForResponse waits for completion of a fact request that was initiated by qr code
func (s Service) WaitForResponse(cid string, exp time.Duration) (*QRFactResponse, error) {
	responder, response, err := s.messaging.Wait(cid, exp)
	if err != nil {
		return nil, err
	}

	selfID := strings.Split(responder, ":")[0]

	facts, err := s.factResponse(selfID, selfID, response)
	if err != nil {
		return nil, err
	}

	return &QRFactResponse{Responder: responder, Facts: facts}, nil
}

func (s *Service) factResponse(issuer, subject string, response []byte) ([]Fact, error) {
	pks, err := s.pki.GetPublicKeys(issuer)
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

	var resp standardresponse

	err = json.Unmarshal(msg, &resp)
	if err != nil {
		return nil, ErrBadJSONPayload
	}

	if resp.Audience != s.selfID {
		return nil, ErrMessageBadAudience
	}

	if resp.Issuer != issuer {
		return nil, ErrMessageBadIssuer
	}

	if ntp.After(resp.ExpiresAt) {
		return nil, ErrMessageExpired
	}

	if ntp.Before(resp.IssuedAt) {
		return nil, ErrMessageIssuedTooSoon
	}

	for i, f := range resp.Facts {
		resp.Facts[i].payloads = make([][]byte, len(f.Attestations))

		for x, adata := range f.Attestations {
			jws, err := jose.ParseSigned(string(adata))
			if err != nil {
				return nil, err
			}

			iss := gjson.GetBytes(jws.UnsafePayloadWithoutVerification(), "iss").String()

			pks, err := s.pki.GetPublicKeys(iss)
			if err != nil {
				return nil, err
			}

			var keys []publickey

			err = json.Unmarshal(pks, &keys)
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

			sub := gjson.GetBytes(msg, "sub").String()

			if sub != subject {
				return nil, ErrBadAttestationSubject
			}

			resp.Facts[i].payloads[x] = msg
		}
	}

	switch resp.Status {
	case StatusAccepted:
		return resp.Facts, nil
	case StatusRejected:
		return nil, ErrStatusRejected
	case StatusUnauthorized:
		return nil, ErrStatusUnauthorized
	default:
		return nil, ErrMessageBadStatus
	}
}

func (s *Service) factPayload(cid, selfID, intermediary, description string, facts []Fact, exp time.Duration) ([]byte, error) {
	request, err := json.Marshal(
		map[string]interface{}{
			"typ":         RequestInformation,
			"cid":         cid,
			"jti":         uuid.New().String(),
			"iss":         s.selfID,
			"sub":         selfID,
			"aud":         intermediary,
			"iat":         ntp.TimeFunc().Format(time.RFC3339),
			"exp":         ntp.TimeFunc().Add(exp).Format(time.RFC3339),
			"device_id":   s.deviceID,
			"description": description,
			"facts":       facts,
		},
	)

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: s.sk}, nil)
	if err != nil {
		return nil, err
	}

	signedRequest, err := signer.Sign(request)
	if err != nil {
		return nil, err
	}

	return []byte(signedRequest.FullSerialize()), nil
}

// builds a list of all devices associated with an identity
func (s Service) recipients(selfID string) ([]string, error) {
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
