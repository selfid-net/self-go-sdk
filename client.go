package selfsdk

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lucasb-eyer/go-colorful"
	"github.com/selfid-net/self-go-sdk/messages"
	messaging "github.com/selfid-net/self-messaging-client"
	msgproto "github.com/selfid-net/self-messaging-proto"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/ed25519"
	"gopkg.in/square/go-jose.v2"
)

const DefaultEndpointTarget = "https://api.selfid.net"
const DefaultMessagingTarget = "wss://messaging.selfid.net/v1/messaging"

// Client self client
type Client struct {
	AppID           string
	PrivateKey      ed25519.PrivateKey
	target          string
	messagingTarget string
	messagingDevice string
	qrcolor         string
	conn            *http.Client
	messaging       *messaging.Client
	requestCache    sync.Map
	handlers        sync.Map
}

// New creates a new self sdk client
func New(appID string, appKey string, opts ...func(c *Client) error) (*Client, error) {
	pk, err := Decode(appKey)
	if err != nil {
		return nil, ErrInvalidKeyEncoding
	}

	c := &Client{
		AppID:           appID,
		PrivateKey:      ed25519.NewKeyFromSeed(pk),
		target:          DefaultEndpointTarget,
		messagingTarget: DefaultMessagingTarget,
		messagingDevice: "1",
		qrcolor:         "#0E1C42",
		conn:            &http.Client{},
	}

	for _, opt := range opts {
		err := opt(c)
		if err != nil {
			return nil, err
		}
	}

	c.messaging, err = messaging.New(c.messagingTarget, appID, c.messagingDevice, appKey)
	if err != nil {
		return nil, err
	}

	// handle all incoming messages
	go c.messages()

	return c, nil
}

func (c *Client) messages() {
	ch := c.messaging.ReceiveChan()

	for {
		msg := <-ch

		msgType := getJWSValue(msg.Ciphertext, "typ")

		if msgType == "" {
			continue
		}

		handle, ok := c.handlers.Load(msgType)
		if !ok {
			continue
		}

		handle.(MessageHandler)(msg)
	}
}

// OnMessage sets a message handler for incoming jws messages of a given type
func (c *Client) OnMessage(msgType string, handler MessageHandler) {
	c.handlers.Store(msgType, handler)
}

// GetApp get an app by its ID
func (c *Client) GetApp(appID string) (*App, error) {
	var m App

	resp, err := c.get("/v1/apps/" + appID)
	if err != nil {
		return nil, err
	}

	return &m, c.readJSON(resp, &m)
}

// GetIdentity get an identity by its ID
func (c *Client) GetIdentity(selfID string) (*Identity, error) {
	var m Identity

	resp, err := c.get("/v1/identities/" + selfID)
	if err != nil {
		return nil, err
	}

	return &m, c.readJSON(resp, &m)
}

// GetDevices gets devices for an identity
func (c *Client) GetDevices(selfID string) ([]string, error) {
	var m []string

	resp, err := c.get("/v1/identities/" + selfID + "/devices")
	if err != nil {
		return nil, err
	}

	return m, c.readJSON(resp, &m)
}

// Authenticate sends an authentication challenge to a given identity
func (c *Client) Authenticate(selfID, callbackURL string) (string, error) {
	u, err := url.Parse(callbackURL)
	if err != nil {
		return "", err
	}

	request := map[string]string{
		"typ":      "authentication_req",
		"cid":      uuid.New().String(),
		"iss":      c.AppID,
		"aud":      u.Hostname(),
		"sub":      selfID,
		"iat":      messaging.TimeFunc().Format(time.RFC3339),
		"exp":      messaging.TimeFunc().Add(time.Minute * 5).Format(time.RFC3339),
		"jti":      uuid.New().String(),
		"callback": callbackURL,
	}

	payload, err := json.Marshal(request)
	if err != nil {
		return request["cid"], err
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: c.PrivateKey}, nil)
	if err != nil {
		return request["cid"], err
	}

	signedPayload, err := signer.Sign(payload)
	if err != nil {
		return request["cid"], err
	}

	_, err = c.post("/v1/auth/", "application/json", []byte(signedPayload.FullSerialize()))

	return request["cid"], err
}

// ValidateAuth validate the authentication response sent by the users device
func (c *Client) ValidateAuth(response []byte) (string, error) {
	payload := make(map[string]string)

	jws, err := jose.ParseSigned(string(response))
	if err != nil {
		return payload["cid"], err
	}

	err = json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &payload)
	if err != nil {
		return payload["cid"], err
	}

	if payload["sub"] == "" {
		return payload["cid"], ErrInvalidAuthSubject
	}

	if payload["iss"] != c.AppID {
		return payload["cid"], ErrInvalidAuthIssuer
	}

	exp, err := time.Parse(time.RFC3339, payload["exp"])
	if err != nil {
		return payload["cid"], err
	}

	if messaging.TimeFunc().After(exp) {
		return payload["cid"], ErrAuthenticationRequestExpired
	}

	kc := newKeyCache(c)

	keys, err := kc.get(payload["sub"])
	if err != nil {
		return payload["cid"], err
	}

	_, err = verify(response, keys)
	if err != nil {
		return payload["cid"], err
	}

	switch payload["status"] {
	case "accepted":
		return payload["cid"], nil
	case "rejected":
		return payload["cid"], ErrAuthRejected
	default:
		return payload["cid"], ErrInvalidAuthStatus
	}
}

// Connect allows connections from the specified SelfID. You can also use '*' to
// permit all senders.
func (c *Client) Connect(selfID string) error {
	return c.messaging.PermitSender(selfID, messaging.TimeFunc().Add(time.Hour*876000))
}

// RequestInformation requests information to an entity
func (c *Client) RequestInformation(r *InformationRequest) (*messages.IdentityInfoResponse, error) {
	cid := uuid.New().String()

	claims, err := r.build(cid, c.AppID)
	if err != nil {
		return nil, err
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: c.PrivateKey}, nil)
	if err != nil {
		return nil, err
	}

	signedPayload, err := signer.Sign(claims)
	if err != nil {
		return nil, err
	}

	devices, err := c.GetDevices(r.recipient())
	if err != nil {
		return nil, err
	}

	if len(devices) < 1 {
		return nil, errors.New("identity has no devices to message")
	}

	// TODO broadcast to all devices
	m := &msgproto.Message{
		Id:         uuid.New().String(),
		Type:       msgproto.MsgType_MSG,
		Sender:     c.AppID + ":" + c.messagingDevice,
		Recipient:  r.recipient() + ":" + devices[0],
		Ciphertext: []byte(signedPayload.FullSerialize()),
	}

	ch, err := c.messaging.JWSRequest(cid, m)
	if err != nil {
		return nil, err
	}

	var rm *msgproto.Message

	select {
	case rm = <-ch:
	case <-time.After(r.Expires):
		return nil, errors.New("request has expired")
	}

	if rm.Sender != m.Recipient {
		return nil, errors.New("response sender does not match the recipient")
	}

	kc := newKeyCache(c)

	keys, err := kc.get(r.recipient())
	if err != nil {
		return nil, err
	}

	payload, err := verify(rm.Ciphertext, keys)
	if err != nil {
		return nil, err
	}

	var resp messages.IdentityInfoResponse

	err = json.Unmarshal(payload, &resp)
	if err != nil {
		return nil, err
	}

	for _, v := range resp.Facts {
		_, err = validate(r.SelfID, v, kc)
		if err != nil {
			return nil, err
		}
	}

	return &resp, nil
}

// GenerateQRCode generates a qr code image containing a signed jws
func (c *Client) GenerateQRCode(reqType string, cid string, fields map[string]interface{}, size int, exp time.Duration) ([]byte, error) {
	if fields == nil {
		return nil, errors.New("must specify valid fields")
	}

	fields["typ"] = "authentication_req"
	fields["cid"] = cid
	fields["iss"] = c.AppID
	fields["sub"] = "-"
	fields["aud"] = "-"
	fields["jti"] = uuid.New().String()
	fields["iat"] = messaging.TimeFunc().Format(time.RFC3339)
	fields["exp"] = messaging.TimeFunc().Add(exp).Format(time.RFC3339)
	fields["device_id"] = c.messagingDevice

	payload, err := json.Marshal(fields)
	if err != nil {
		return nil, err
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: c.PrivateKey}, nil)
	if err != nil {
		return nil, err
	}

	signedPayload, err := signer.Sign(payload)
	if err != nil {
		return nil, err
	}

	q, err := qrcode.New(signedPayload.FullSerialize(), qrcode.Low)
	if err != nil {
		return nil, err
	}

	q.BackgroundColor, _ = colorful.Hex("#FFFFFF")
	q.ForegroundColor, _ = colorful.Hex(c.qrcolor)

	return q.PNG(size)
}

func (c *Client) respond(requestID string, err error) {
	ch, _ := c.requestCache.LoadOrStore(requestID, make(chan error))
	ch.(chan error) <- err
}
