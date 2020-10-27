package messaging

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/joinself/self-go-sdk/pkg/crypto"
	"github.com/joinself/self-go-sdk/pkg/transport"
	"github.com/tidwall/gjson"
	"golang.org/x/crypto/ed25519"
)

var decoder = base64.RawURLEncoding

type subscription func(sender string, payload []byte)

type response struct {
	sender  string
	payload []byte
}

// Transport the stateful connection used to send and receive messages
type Transport interface {
	Send(recipients []string, data []byte) error
	Receive() (string, []byte, error)
	Command(command string, payload []byte) ([]byte, error)
	Close() error
}

// Cryto the crytographic provider used to encrypt and decrypt messages
type Crypto interface {
	Encrypt(recipients []string, plaintext []byte) ([]byte, error)
	Decrypt(sender string, ciphertext []byte) ([]byte, error)
}

// Config messaging configuration for connecting to self messaging
type Config struct {
	SelfID       string
	DeviceID     string
	PrivateKey   ed25519.PrivateKey
	MessagingURL string
	APIURL       string
	Transport    Transport
	Crypto       Crypto
}

// Client default implementation of a messaging client
type Client struct {
	config        Config
	crypto        Crypto
	transport     Transport
	responses     sync.Map
	subscriptions sync.Map
}

// New create a new messaging client
func New(config Config) (*Client, error) {
	if config.Transport == nil {
		cfg := transport.WebsocketConfig{
			SelfID:       config.SelfID,
			DeviceID:     config.DeviceID,
			PrivateKey:   config.PrivateKey,
			MessagingURL: config.MessagingURL,
		}

		ws, err := transport.NewWebsocket(cfg)
		if err != nil {
			return nil, err
		}

		config.Transport = ws
	}

	if config.Crypto == nil {
		cfg := crypto.Config{
			SelfID:     config.SelfID,
			PrivateKey: config.PrivateKey,
		}

		cr, err := crypto.New(cfg)
		if err != nil {
			return nil, err
		}

		config.Crypto = cr
	}

	c := Client{
		config:    config,
		responses: sync.Map{},
		transport: config.Transport,
		crypto:    config.Crypto,
	}

	go c.reader()

	return &c, nil
}

// Send sends an encypted message to recipients
func (c *Client) Send(recipients []string, plaintext []byte) error {
	ciphertext, err := c.crypto.Encrypt(recipients, plaintext)
	if err != nil {
		return err
	}

	return c.transport.Send(recipients, ciphertext)
}

// Request sends a request to a specified identity and blocks until response is received
func (c *Client) Request(recipients []string, cid string, data []byte, timeout time.Duration) (string, []byte, error) {
	err := c.Send(recipients, data)
	if err != nil {
		return "", nil, err
	}

	return c.Wait(cid, timeout)
}

// Register registers a conversation
func (c *Client) Register(cid string) {
	c.responses.LoadOrStore(cid, make(chan response, 1))
}

// Wait waits for a response from a given conversation
func (c *Client) Wait(cid string, timeout time.Duration) (string, []byte, error) {
	r, _ := c.responses.LoadOrStore(cid, make(chan response, 1))

	if timeout == 0 {
		resp := <-r.(chan response)
		return resp.sender, resp.payload, nil
	}

	select {
	case resp := <-r.(chan response):
		return resp.sender, resp.payload, nil
	case <-time.After(timeout):
		return "", nil, errors.New("request timed out")
	}
}

// Subscribe subscribes to a given message type
// @param {String} message type to subscribe to [authentication.RequestAuthentication|
// authentication.ResponseAuthentication|fact.RequestInformation|fact.ResponseInformation]
func (c *Client) Subscribe(msgType string, sub func(sender string, payload []byte)) {
	c.subscriptions.Store(msgType, sub)
}

// Command sends a command to the messaging server to be fulfilled
func (c *Client) Command(command string, payload []byte) ([]byte, error) {
	return c.transport.Command(command, payload)
}

// Close gracefully closes down the messaging cient
func (c *Client) Close() error {
	return nil
}

// ListConnections lists all self IDs that are permitted to send messages
func (c *Client) ListConnections() ([]string, error) {
	var rules []string

	resp, err := c.Command("acl.list", nil)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(resp, &rules)
	if err != nil {
		return nil, err
	}

	return rules, nil
}

// IsPermittingConnectionsFrom checks if the current connection is permitting connections from
func (c *Client) IsPermittingConnectionsFrom(selfid string) bool {
	conns, err := c.ListConnections()
	if err != nil {
		return false
	}
	for _, c := range conns {
		if c == selfid || c == "*" {
			return true
		}
	}
	return false
}

func (c *Client) reader() {
	for {
		sender, ciphertext, err := c.transport.Receive()
		if err != nil {
			log.Println("messaging:", err)
			return
		}

		plaintext, err := c.crypto.Decrypt(sender, ciphertext)
		if err != nil {
			log.Println("messaging:", err)
			continue
		}

		encPayload := gjson.GetBytes(plaintext, "payload").String()
		if encPayload == "" {
			return
		}

		payload, err := decoder.DecodeString(encPayload)
		if err != nil {
			log.Println("messaging:", err)
			return
		}

		cid := gjson.GetBytes(payload, "cid").String()

		ch, ok := c.responses.Load(cid)
		if ok {
			ch.(chan response) <- response{sender, plaintext}
			continue
		}

		typ := gjson.GetBytes(payload, "typ").String()
		fn, ok := c.subscriptions.Load(typ)
		if ok {
			go fn.(func(sender string, plaintext []byte))(sender, plaintext)
			continue
		}
	}
}
