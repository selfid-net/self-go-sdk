// Copyright 2020 Self Group Ltd. All Rights Reserved.

package pki

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/joinself/self-go-sdk/pkg/transport"
	"golang.org/x/crypto/ed25519"
)

// Transport the stateful connection used to send and receive messages
type Transport interface {
	Get(path string) ([]byte, error)
	Post(path, contentType string, payload []byte) ([]byte, error)
}

// Config messaging configuration for connecting to self messaging
type Config struct {
	SelfID     string
	PrivateKey ed25519.PrivateKey
	APIURL     string
	Transport  Transport
}

// Client default implementation of a messaging client
type Client struct {
	config    Config
	transport Transport
}

// New create a new messaging client
func New(config Config) (*Client, error) {
	c := Client{
		config: config,
	}

	if config.Transport == nil {
		cfg := transport.RestConfig{
			SelfID:     config.SelfID,
			PrivateKey: config.PrivateKey,
			APIURL:     config.APIURL,
			Client:     &http.Client{},
		}

		rs, err := transport.NewRest(cfg)
		if err != nil {
			return nil, err
		}

		config.Transport = rs
	}

	c.transport = config.Transport

	return &c, nil
}

// GetHistory gets an identities public keys
func (c *Client) GetHistory(selfID string) ([]json.RawMessage, error) {
	var path string

	if len(selfID) > 11 {
		path = fmt.Sprintf("/v1/apps/%s/history", selfID)
	} else {
		path = fmt.Sprintf("/v1/identities/%s/history", selfID)
	}

	var history []json.RawMessage

	data, err := c.transport.Get(path)
	if err != nil {
		return nil, err
	}

	return history, json.Unmarshal(data, &history)
}

// GetDeviceKey gets an identities one time device key
func (c *Client) GetDeviceKey(selfID, deviceID string) ([]byte, error) {
	var path string

	if len(selfID) > 11 {
		path = fmt.Sprintf("/v1/apps/%s/devices/%s/pre_keys", selfID, deviceID)
	} else {
		path = fmt.Sprintf("/v1/identities/%s/devices/%s/pre_keys", selfID, deviceID)
	}

	return c.transport.Get(path)
}

// SetDeviceKeys updates an identites device prekey bundle
func (c *Client) SetDeviceKeys(selfID, deviceID string, pkb []byte) error {
	var path string

	if len(selfID) > 11 {
		path = fmt.Sprintf("/v1/apps/%s/devices/%s/pre_keys", selfID, deviceID)
	} else {
		path = fmt.Sprintf("/v1/identities/%s/devices/%s/pre_keys", selfID, deviceID)
	}

	_, err := c.transport.Post(path, "application/json", pkb)
	return err
}
