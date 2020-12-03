// Copyright 2020 Self Group Ltd. All Rights Reserved.

package siggraph

import (
	"encoding/base64"
	"encoding/json"

	"golang.org/x/crypto/ed25519"

	"gopkg.in/square/go-jose.v2"
)

var dec = base64.RawURLEncoding

// Operation represents a set of actions to perform
// An operation can contain a number of actions that
// add and revoke keys of different types
type Operation struct {
	Sequence  int      `json:"sequence"`  // sequence id
	Previous  string   `json:"previous"`  // signature of the previous operation
	Version   string   `json:"version"`   // the version of operation
	Timestamp int64    `json:"timestamp"` // unix timestamp
	Actions   []Action `json:"actions"`   // list of actionable operations
	jws       *jose.JSONWebSignature
	hdr       Header
	sig       string
}

// ParseOperation parses a jws object into an operation
func ParseOperation(operation json.RawMessage) (*Operation, error) {
	var op Operation
	var jws JWS

	err := json.Unmarshal(operation, &jws)
	if err != nil {
		return nil, err
	}

	op.jws, err = jose.ParseSigned(string(operation))
	if err != nil {
		return nil, err
	}

	hdr, err := dec.DecodeString(jws.Protected)
	if err != nil {
		return nil, err
	}

	pay, err := dec.DecodeString(jws.Payload)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(pay, &op)
	if err != nil {
		return nil, err
	}

	op.sig = jws.Signature

	err = json.Unmarshal(hdr, &op.hdr)
	if err != nil {
		return nil, err
	}

	if op.Version != "1.0.0" {
		return nil, ErrInvalidOperationVersion
	}

	if op.Sequence < 0 {
		return nil, ErrSequenceOutOfOrder
	}

	if op.Timestamp < 1 {
		return nil, ErrInvalidTimestamp
	}

	if len(op.Actions) < 1 {
		return nil, ErrOperationNOOP
	}

	return &op, nil
}

// SignatureKeyID returns the key identifier for the key that signed the request
func (o *Operation) SignatureKeyID() string {
	return o.hdr.KeyID
}

// Verify validates the signature of an operation with an ed25519 key
func (o *Operation) Verify(key ed25519.PublicKey) error {
	_, err := o.jws.Verify(key)
	return err
}

// ActionByKID gets the action by its key identifier
func (o *Operation) ActionByKID(kid string) *Action {
	for _, a := range o.Actions {
		if a.KID == kid {
			return &a
		}
	}

	return nil
}
