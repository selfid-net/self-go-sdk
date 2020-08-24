package fact

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
	ErrMissingConversationID        = errors.New("deep link request must specify a unique conversation id")
	ErrMissingCallback              = errors.New("deep link request must specify a callback url")
	ErrFactRequestCID               = errors.New("cid not provided")
	ErrSigningKeyInvalid            = errors.New("signing key was invalid at the time the attestation was issued")

	ServiceSelfIntermediary = "self_intermediary"
)

// FactRequest specifies the parameters of an information request
type FactRequest struct {
	SelfID      string
	Description string
	Facts       []Fact
	Expiry      time.Duration
}

// FactRequestAsync specifies the parameters of an information requestAsync
type FactRequestAsync struct {
	SelfID      string
	Description string
	Facts       []Fact
	Expiry      time.Duration
	CID         string
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
	Options        map[string]string
	Expiry         time.Duration
	QRConfig       QRConfig
}

// QRFactResponse contains the details of the requested facts
type QRFactResponse struct {
	Responder string
	Facts     []Fact
	Options   map[string]string
}

// DeepLinkFactRequest contains the details of the requested facts
type DeepLinkFactRequest struct {
	ConversationID string
	Description    string
	Callback       string
	Facts          []Fact
	Expiry         time.Duration
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

	payload, err := s.factPayload(cid, req.SelfID, req.SelfID, req.Description, req.Facts, nil, req.Expiry)
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

// RequestAsync requests a fact from a given identity and does not
// wait for the response
func (s Service) RequestAsync(req *FactRequestAsync) error {
	if req.SelfID == "" {
		return ErrFactRequestBadIdentity
	}

	if len(req.Facts) < 1 {
		return ErrFactRequestBadFacts
	}

	if req.Expiry == 0 {
		req.Expiry = defaultRequestTimeout
	}

	if req.CID == "" {
		return ErrFactRequestCID
	}

	payload, err := s.factPayload(req.CID, req.SelfID, req.SelfID, req.Description, req.Facts, nil, req.Expiry)
	if err != nil {
		return err
	}

	recipients, err := s.recipients(req.SelfID)
	if err != nil {
		return err
	}

	return s.messaging.Send(recipients, payload)
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

	payload, err := s.factPayload(cid, req.SelfID, req.Intermediary, req.Description, req.Facts, nil, req.Expiry)
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

// GenerateQRCode generates a qr code containing an fact request
func (s Service) GenerateQRCode(req *QRFactRequest) ([]byte, error) {
	if req.ConversationID == "" {
		return nil, ErrFactQRRequestBadConversation
	}

	if req.Expiry == 0 {
		req.Expiry = defaultRequestTimeout
	}
	// TODO(@adriacidre) should we check the facts length to avoid empty arrays?

	if req.QRConfig.ForegroundColor == "" {
		req.QRConfig.ForegroundColor = "#0E1C42"
	}

	if req.QRConfig.BackgroundColor == "" {
		req.QRConfig.BackgroundColor = "#FFFFFF"
	}

	if req.QRConfig.Size == 0 {
		req.QRConfig.Size = 400
	}

	payload, err := s.factPayload(req.ConversationID, "-", "-", req.Description, req.Facts, req.Options, req.Expiry)
	if err != nil {
		return nil, err
	}

	q, err := qrcode.New(string(payload), qrcode.Low)
	if err != nil {
		return nil, err
	}

	q.BackgroundColor, _ = colorful.Hex(req.QRConfig.BackgroundColor)
	q.ForegroundColor, _ = colorful.Hex(req.QRConfig.ForegroundColor)

	if req.ConversationID != "-" {
		s.messaging.Register(req.ConversationID)
	}

	return q.PNG(req.QRConfig.Size)
}

// GenerateDeepLink generates a qr code containing an fact request
func (s Service) GenerateDeepLink(req *DeepLinkFactRequest) (string, error) {
	if req.ConversationID == "" {
		return "", ErrMissingConversationID
	}

	if req.Callback == "" {
		return "", ErrMissingCallback
	}
	// TODO(@adriacidre) should we check the facts length to avoid empty arrays?

	payload, err := s.factPayload(req.ConversationID, "-", "-", req.Description, req.Facts, nil, req.Expiry)
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
	history, err := s.pki.GetHistory(issuer)
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

	jws, err := jose.ParseSigned(string(response))
	if err != nil {
		return nil, err
	}

	msg, err := jws.Verify(pk)
	if err != nil {
		return nil, ErrResponseBadSignature
	}

	return s.FactResponse(issuer, subject, msg)
}

// FactResponse validate and process a fact response
func (s *Service) FactResponse(issuer, subject string, response []byte) ([]Fact, error) {
	var resp standardresponse

	err := json.Unmarshal(response, &resp)
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

			apayload := jws.UnsafePayloadWithoutVerification()

			iss := gjson.GetBytes(apayload, "iss").String()
			iatRFC3999 := gjson.GetBytes(apayload, "iat").String()

			history, err := s.pki.GetHistory(iss)
			if err != nil {
				return nil, err
			}

			sg, err := siggraph.New(history)
			if err != nil {
				return nil, err
			}

			kid, err := getJWSKID(adata)
			if err != nil {
				return nil, err
			}

			iat, err := time.Parse(time.RFC3339, iatRFC3999)
			if err != nil {
				return nil, err
			}

			if !sg.IsKeyValid(kid, iat.Unix()) {
				return nil, ErrSigningKeyInvalid
			}

			pk, err := sg.Key(kid)
			if err != nil {
				return nil, err
			}

			msg, err := jws.Verify(pk)
			if err != nil {
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

func (s *Service) factPayload(cid, selfID, intermediary, description string, facts []Fact, options map[string]string, exp time.Duration) ([]byte, error) {
	req := map[string]interface{}{
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
	}

	if options != nil {
		req["options"] = options
	}

	request, err := json.Marshal(req)
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
