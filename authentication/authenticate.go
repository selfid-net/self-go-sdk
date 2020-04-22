package authentication

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
)

var (
	ErrMissingConversationID  = errors.New("qr request must specify a unique conversation id")
	ErrRequestTimeout         = errors.New("request timeout")
	ErrResponseBadType        = errors.New("received response is not an authentication response")
	ErrResponseBadIssuer      = errors.New("bad response issuer")
	ErrResponseBadAudience    = errors.New("bad response audience")
	ErrResponseBadSubject     = errors.New("bad response subject")
	ErrResponseBadSignature   = errors.New("bad response signature")
	ErrResponseBadStatus      = errors.New("bad response status")
	ErrInvalidExpiry          = errors.New("invalid expiry format")
	ErrInvalidIssuedAt        = errors.New("invalid issued at format")
	ErrResponseExpired        = errors.New("response has expired")
	ErrResponseIssuedTooSoon  = errors.New("response was issued in the future")
	ErrResponseStatusRejected = errors.New("authentication was rejected")
)

// QRAuthenticationRequest specifies options in a qr code authentication request
type QRAuthenticationRequest struct {
	ConversationID string
	Expiry         time.Duration
	QRConfig       QRConfig
}

// QRConfig specifies options for generating a qr code
type QRConfig struct {
	Size            int
	ForegroundColor string
	BackgroundColor string
}

// Request prompts a user to authenticate via biometrics
func (s Service) Request(selfID string) error {
	cid := uuid.New().String()

	req, err := s.authenticationPayload(cid, selfID, s.expiry)
	if err != nil {
		return err
	}

	recipients, err := s.recipients(selfID)
	if err != nil {
		return err
	}

	_, resp, err := s.messaging.Request(recipients, cid, req)
	if err != nil {
		return err
	}

	return s.authenticationResponse(selfID, resp)
}

// GenerateQRCode generates an authentication request as a qr code
func (s *Service) GenerateQRCode(req *QRAuthenticationRequest) ([]byte, error) {
	if req.ConversationID == "" {
		return nil, ErrMissingConversationID
	}

	if req.Expiry == 0 {
		req.Expiry = time.Minute * 5
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

	payload, err := s.authenticationPayload(req.ConversationID, "", req.Expiry)
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

// WaitForResponse waits for a response from a qr code authentication request
func (s *Service) WaitForResponse(cid string, exp time.Duration) error {
	responder, resp, err := s.messaging.Wait(cid, exp)
	if err != nil {
		return err
	}

	selfID := strings.Split(responder, ":")[0]

	return s.authenticationResponse(selfID, resp)
}

func (s *Service) authenticationResponse(selfID string, resp []byte) error {
	var payload map[string]string

	jws, err := jose.ParseSigned(string(resp))
	if err != nil {
		return err
	}

	err = json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &payload)
	if err != nil {
		return err
	}

	if payload["typ"] != "authentication_resp" {
		return ErrResponseBadType
	}

	if payload["aud"] != s.selfID {
		return ErrResponseBadAudience
	}

	if payload["iss"] != selfID {
		return ErrResponseBadIssuer
	}

	if payload["sub"] != selfID {
		return ErrResponseBadSubject
	}

	exp, err := time.Parse(time.RFC3339, payload["exp"])
	if err != nil {
		return ErrInvalidExpiry
	}

	if ntp.TimeFunc().After(exp) {
		return ErrResponseExpired
	}

	iat, err := time.Parse(time.RFC3339, payload["iat"])
	if err != nil {
		return ErrInvalidIssuedAt
	}

	if iat.After(ntp.TimeFunc()) {
		return ErrResponseIssuedTooSoon
	}

	var keys []publickey

	keyData, err := s.pki.GetPublicKeys(selfID)
	if err != nil {
		return err
	}

	err = json.Unmarshal(keyData, &keys)
	if err != nil {
		return err
	}

	var verified bool

	for _, k := range keys {
		_, err = jws.Verify(k.pk())
		if err == nil {
			verified = true
			break
		}
	}

	if !verified {
		return ErrResponseBadSignature
	}

	switch payload["status"] {
	case "accepted":
		return nil
	case "rejected":
		return ErrResponseStatusRejected
	default:
		return ErrResponseBadStatus
	}
}

func (s *Service) authenticationPayload(cid, selfID string, exp time.Duration) ([]byte, error) {
	if selfID == "" {
		selfID = "-"
	}

	req := map[string]string{
		"jti":       uuid.New().String(),
		"cid":       cid,
		"typ":       "authentication_req",
		"iss":       s.selfID,
		"aud":       selfID,
		"sub":       selfID,
		"iat":       ntp.TimeFunc().Format(time.RFC3339),
		"exp":       ntp.TimeFunc().Add(exp).Format(time.RFC3339),
		"device_id": s.deviceID,
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: s.sk}, nil)
	if err != nil {
		return nil, err
	}

	signature, err := signer.Sign(payload)
	if err != nil {
		return nil, err
	}

	return []byte(signature.FullSerialize()), nil
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
