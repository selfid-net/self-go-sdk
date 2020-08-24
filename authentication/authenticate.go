package authentication

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/joinself/self-go-sdk/pkg/ntp"
	"github.com/joinself/self-go-sdk/pkg/siggraph"
	"github.com/lucasb-eyer/go-colorful"
	"github.com/skip2/go-qrcode"
	"github.com/square/go-jose"
)

var (
	ErrMissingConversationID      = errors.New("qr request must specify a unique conversation id")
	ErrRequestTimeout             = errors.New("request timeout")
	ErrResponseBadType            = errors.New("received response is not an authentication response")
	ErrResponseBadIssuer          = errors.New("bad response issuer")
	ErrResponseBadAudience        = errors.New("bad response audience")
	ErrResponseBadSubject         = errors.New("bad response subject")
	ErrResponseBadSignature       = errors.New("bad response signature")
	ErrResponseBadStatus          = errors.New("bad response status")
	ErrInvalidExpiry              = errors.New("invalid expiry format")
	ErrInvalidIssuedAt            = errors.New("invalid issued at format")
	ErrResponseExpired            = errors.New("response has expired")
	ErrResponseIssuedTooSoon      = errors.New("response was issued in the future")
	ErrResponseStatusRejected     = errors.New("authentication was rejected")
	ErrMissingConversationIDForDL = errors.New("deep link request must specify a unique conversation id")
	ErrMissingCallback            = errors.New("deep link request must specify a callback url")
)

// QRAuthenticationRequest specifies options in a qr code authentication request
type QRAuthenticationRequest struct {
	ConversationID string
	Expiry         time.Duration
	QRConfig       QRConfig
}

// DeepLinkAuthenticationRequest specifies options in a deep link authentication request
type DeepLinkAuthenticationRequest struct {
	Callback       string
	ConversationID string
	Expiry         time.Duration
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

// RequestAsync prompts a user to authenticate via biometrics but
// does not wait for the response.
func (s Service) RequestAsync(selfID, cid string) error {
	req, err := s.authenticationPayload(cid, selfID, s.expiry)
	if err != nil {
		return err
	}

	recipients, err := s.recipients(selfID)
	if err != nil {
		return err
	}

	return s.messaging.Send(recipients, req)
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

// GenerateDeepLink generates an authentication request as a deep link
func (s *Service) GenerateDeepLink(req *DeepLinkAuthenticationRequest) (string, error) {
	if req.ConversationID == "" {
		return "", ErrMissingConversationIDForDL
	}

	if req.Callback == "" {
		return "", ErrMissingCallback
	}

	if req.Expiry == 0 {
		req.Expiry = time.Minute * 5
	}

	payload, err := s.authenticationPayload(req.ConversationID, "", req.Expiry)
	if err != nil {
		return "", err
	}

	s.messaging.Register(req.ConversationID)

	url := "https://selfid.page.link/?link=" + req.Callback + "%3Fqr=" + base64.RawStdEncoding.EncodeToString(payload)
	if s.environment == "" {
		return url + "&apn=net.selfid.app", nil
	} else if s.environment == "development" {
		return url + "&apn=net.selfid.app.dev", nil
	}
	return url + "&apn=net.selfid.app." + s.environment, nil
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

	if payload["typ"] != "identities.authenticate.resp" {
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

	if ntp.After(exp) {
		return ErrResponseExpired
	}

	iat, err := time.Parse(time.RFC3339, payload["iat"])
	if err != nil {
		return ErrInvalidIssuedAt
	}

	if ntp.Before(iat) {
		return ErrResponseIssuedTooSoon
	}

	history, err := s.pki.GetHistory(selfID)
	if err != nil {
		return err
	}

	sg, err := siggraph.New(history)
	if err != nil {
		return err
	}

	kid, err := getJWSKID(resp)
	if err != nil {
		return err
	}

	pk, err := sg.ActiveKey(kid)
	if err != nil {
		return err
	}

	_, err = jws.Verify(pk)
	if err != nil {
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
		"typ":       "identities.authenticate.req",
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

	opts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": s.keyID,
		},
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: s.sk}, opts)
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
