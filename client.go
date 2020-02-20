package selfsdk

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
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
	reconnect       bool
	conn            *http.Client
	messaging       *messaging.Client
	requestCache    sync.Map
	handlers        sync.Map
}

// QR Code config
type qrConfig struct {
	expiry   time.Duration
	fields   map[string]interface{}
	size     int
	qrcolorf string
	qrcolorb string
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
		reconnect:       true,
		conn:            &http.Client{},
	}

	for _, opt := range opts {
		err := opt(c)
		if err != nil {
			return nil, err
		}
	}

	c.messaging, err = messaging.New(c.messagingTarget, appID, c.messagingDevice, appKey, messaging.AutoReconnect(c.reconnect))
	if err != nil {
		return nil, err
	}

	// handle all incoming messages
	go c.messages()

	return c, nil
}

func (c *Client) messages() {
	for {
		msg, err := c.messaging.Receive()
		if err != nil {
			log.Println("error receving messages:", err)
			continue
		}

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

// WaitForResponse waits for a response for a given conversation id
func (c *Client) WaitForResponse(cid string, timeout time.Duration) (*msgproto.Message, error) {
	return c.messaging.JWSResponse(cid, timeout)
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
func (c *Client) Authenticate(selfID string) error {
	request := map[string]string{
		"typ": "authentication_req",
		"cid": uuid.New().String(),
		"iss": c.AppID,
		"sub": selfID,
		"aud": selfID,
		"iat": messaging.TimeFunc().Format(time.RFC3339),
		"exp": messaging.TimeFunc().Add(time.Minute * 5).Format(time.RFC3339),
		"jti": uuid.New().String(),
	}

	c.messaging.JWSRegister(request["cid"])

	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: c.PrivateKey}, nil)
	if err != nil {
		return err
	}

	signedPayload, err := signer.Sign(payload)
	if err != nil {
		return err
	}

	_, err = c.post("/v1/auth/", "application/json", []byte(signedPayload.FullSerialize()))
	if err != nil {
		return err
	}

	response, err := c.messaging.JWSResponse(request["cid"], time.Minute)
	if err != nil {
		return err
	}

	return c.ValidateAuth(response.Ciphertext)
}

// ValidateAuth validate the authentication response sent by the users device
func (c *Client) ValidateAuth(response []byte) error {
	payload := make(map[string]string)

	jws, err := jose.ParseSigned(string(response))
	if err != nil {
		return err
	}

	err = json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &payload)
	if err != nil {
		return err
	}

	if payload["aud"] != c.AppID {
		return ErrInvalidAuthSubject
	}

	exp, err := time.Parse(time.RFC3339, payload["exp"])
	if err != nil {
		return err
	}

	if messaging.TimeFunc().After(exp) {
		return ErrAuthenticationRequestExpired
	}

	kc := newKeyCache(c)

	keys, err := kc.get(payload["iss"])
	if err != nil {
		return err
	}

	_, err = verify(response, keys)
	if err != nil {
		return err
	}

	switch payload["status"] {
	case "accepted":
		return nil
	case "rejected":
		return ErrAuthRejected
	default:
		return ErrInvalidAuthStatus
	}
}

// PermitConnection permits communication from the specified Self ID.
// You can also use '*' to permit communication from all Self IDs.
func (c *Client) PermitConnection(selfID string) error {
	return c.messaging.PermitSender(selfID, messaging.TimeFunc().Add(time.Hour*876000))
}

// RevokeConnection removes a previously permitted connection based on the
// specified Self ID.
func (c *Client) RevokeConnection(selfID string) error {
	return c.messaging.BlockSender(selfID)
}

// AllowedConnections returns a list of permitted connections.
func (c *Client) AllowedConnections() ([]string, error) {
	rules, err := c.messaging.ListACLRules()
	if err != nil {
		return nil, err
	}

	list := make([]string, len(rules))

	for i, r := range rules {
		list[i] = r.Source
	}

	return list, nil
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
		data, err := base64.RawStdEncoding.DecodeString(string(v))
		if err != nil {
			return nil, err
		}

		_, err = validate(r.SelfID, data, kc)
		if err != nil {
			return nil, err
		}
	}

	return &resp, nil
}

// GenerateQRCode generates a qr code image containing a signed jws
func (c *Client) GenerateQRCode(reqType string, cid string, opts ...func(c *qrConfig) error) ([]byte, error) {
	qrc := &qrConfig{
		expiry:   time.Minute * 5,
		fields:   make(map[string]interface{}),
		size:     400,
		qrcolorf: "#0E1C42",
		qrcolorb: "#FFFFFF",
	}

	for _, opt := range opts {
		err := opt(qrc)
		if err != nil {
			return nil, err
		}
	}

	// setup a handler for the response
	c.messaging.JWSRegister(cid)

	qrc.fields["typ"] = reqType
	qrc.fields["cid"] = cid
	qrc.fields["iss"] = c.AppID
	qrc.fields["sub"] = "-"
	qrc.fields["aud"] = "-"
	qrc.fields["jti"] = uuid.New().String()
	qrc.fields["iat"] = messaging.TimeFunc().Format(time.RFC3339)
	qrc.fields["exp"] = messaging.TimeFunc().Add(qrc.expiry).Format(time.RFC3339)
	qrc.fields["device_id"] = c.messagingDevice

	payload, err := json.Marshal(qrc.fields)
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

	q.BackgroundColor, _ = colorful.Hex(qrc.qrcolorb)
	q.ForegroundColor, _ = colorful.Hex(qrc.qrcolorf)

	return q.PNG(qrc.size)
}

func (c *Client) respond(requestID string, err error) {
	ch, _ := c.requestCache.LoadOrStore(requestID, make(chan error))
	ch.(chan error) <- err
}
