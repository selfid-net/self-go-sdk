// Copyright 2020 Self Group Ltd. All Rights Reserved.

package siggraph

import (
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/crypto/ed25519"
)

// SignatureGraph creates a signature graph
type SignatureGraph struct {
	root    *Node            // root node of the key graph
	keys    map[string]*Node // index of keys by key identifer
	devices map[string]*Node // index of active keys by their device identifier
	sigs    map[string]int   // index of signatures and their sequence
	ops     []*Operation     // array of decoded operations
	rk      *Node            // current active recovery key
}

// New creates a new signature graph from an identities history
func New(history []json.RawMessage) (*SignatureGraph, error) {
	s := SignatureGraph{
		keys:    make(map[string]*Node),
		devices: make(map[string]*Node),
		sigs:    make(map[string]int),
	}

	for _, operation := range history {
		err := s.Execute(operation)
		if err != nil {
			return nil, err
		}
	}

	return &s, nil
}

// Execute executes an operation on the signature graph
func (s *SignatureGraph) Execute(operation json.RawMessage) error {
	// parse and validate the operation config
	op, err := ParseOperation(operation)
	if err != nil {
		return err
	}

	// check the sequence is in order
	if op.Sequence != len(s.ops) {
		return ErrSequenceOutOfOrder
	}

	if op.Sequence > 0 {
		// check the previous signature matches, if not the first (root) operation
		ps, ok := s.sigs[op.Previous]
		if !ok {
			return ErrInvalidPreviousSignature
		}

		if ps != len(s.ops)-1 {
			return ErrInvalidPreviousSignature
		}

		// check the timestamp is greater than the previous operations
		if s.ops[len(s.ops)-1].Timestamp >= op.Timestamp {
			return ErrInvalidTimestamp
		}

		// check the key used to sign the identity exists
		sk, ok := s.keys[op.SignatureKeyID()]
		if !ok {
			return ErrInvalidSigningKey
		}

		// check the signign key hasn't been revoked before the operation
		if sk.ra > 0 && op.Timestamp > sk.ra {
			return ErrSignatureKeyRevoked
		}

		// if this operation is an account recovery, check that it revokes the active recovery key
		if sk.typ == TypeRecoveryKey {
			ka := op.ActionByKID(op.SignatureKeyID())
			if ka == nil {
				return ErrInvalidAccountRecoveryAction
			}

			if ka.Action != ActionKeyRevoke {
				return ErrInvalidAccountRecoveryAction
			}
		}
	}

	// run actions
	for _, a := range op.Actions {
		err := a.Validate()
		if err != nil {
			return err
		}

		switch a.Action {
		case ActionKeyAdd:
			err = s.add(op, &a)
		case ActionKeyRevoke:
			err = s.revoke(op, &a)
		}

		if err != nil {
			return err
		}
	}

	sk, ok := s.keys[op.SignatureKeyID()]
	if !ok {
		return ErrInvalidSigningKey
	}

	// check that the operation was signed before the signing key was revoked
	if op.Timestamp < sk.ca || sk.ra > 0 && op.Timestamp > sk.ra {
		return ErrSignatureKeyRevoked
	}

	// verify the signature of the operation
	err = op.Verify(sk.pk)
	if err != nil {
		return ErrInvalidOperationSignature
	}

	// check all keys to ensure that at least one key is active
	var valid bool

	for _, k := range s.keys {
		if k.ra == 0 {
			valid = true
			break
		}
	}

	if !valid {
		return ErrNoValidKeys
	}

	// check there is an active recovery key
	if s.rk == nil {
		return ErrNoValidRecoveryKey
	}

	if s.rk.ra > 0 {
		return ErrNoValidRecoveryKey
	}

	// add the operation to the history
	s.ops = append(s.ops, op)
	s.sigs[op.sig] = op.Sequence

	return nil
}

// IsKeyValid checks if a key was valid for a given period of time
func (s *SignatureGraph) IsKeyValid(kid string, at int64) bool {
	k, ok := s.keys[kid]
	if !ok {
		return false
	}

	if k.ca <= at && k.ra == 0 || k.ca <= at && k.ra > at {
		return true
	}

	return false
}

// Key gets a device public key key by its identifier
func (s *SignatureGraph) Key(kid string) (ed25519.PublicKey, error) {
	k, ok := s.keys[kid]
	if !ok {
		return nil, ErrKeyNotFound
	}

	if k.typ != TypeDeviceKey {
		return nil, ErrKeyNotFound
	}

	return k.pk, nil
}

// ActiveKey gets an active/valid key by its identifier. An error will be returned if the key has been revoked
func (s *SignatureGraph) ActiveKey(kid string) (ed25519.PublicKey, error) {
	k, ok := s.keys[kid]
	if !ok {
		return nil, ErrKeyNotFound
	}

	if k.typ != TypeDeviceKey {
		return nil, ErrKeyNotFound
	}

	if k.ra > 0 {
		return nil, ErrKeyRevoked
	}

	return k.pk, nil
}

// ActiveDevice gets an active/valid key for a given device identifier. An error will be returned if the key has been revoked
func (s *SignatureGraph) ActiveDevice(did string) (ed25519.PublicKey, error) {
	k, ok := s.devices[did]
	if !ok {
		return nil, ErrKeyNotFound
	}

	if k.typ != TypeDeviceKey {
		return nil, ErrKeyNotFound
	}

	if k.ra > 0 {
		return nil, ErrKeyRevoked
	}

	return k.pk, nil
}

func (s *SignatureGraph) add(op *Operation, a *Action) error {
	// lookup the key the action refers to
	n, ok := s.keys[a.KID]

	// if the key already exists, fail
	if ok {
		return ErrKeyDuplicate
	}

	pk, err := dec.DecodeString(a.Key)
	if err != nil {
		return ErrInvalidKeyEncoding
	}

	n = &Node{
		kid: a.KID,
		did: a.DID,
		typ: a.Type,
		seq: op.Sequence,
		ca:  op.Timestamp,
		ra:  0,
		pk:  ed25519.PublicKey(pk),
	}

	switch a.Type {
	case TypeDeviceKey:
		// check there are no devices with an active key
		d, ok := s.devices[a.DID]
		if ok {
			if d.ra < 1 {
				return ErrMultipleActiveDeviceKeys
			}
		}
	case TypeRecoveryKey:
		// check there are only one active recovery keys
		if s.rk != nil {
			if s.rk.ra == 0 {
				return ErrMultipleActiveRecoveryKeys
			}
		}

		s.rk = n
	}

	s.keys[a.KID] = n
	s.devices[a.DID] = n

	// mutually connect the two nodes
	// if the current key is the signer of the first (root)
	// operation, make it the root of the graph
	if op.Sequence == 0 && op.SignatureKeyID() == a.KID {
		s.root = n
	} else {
		p := s.keys[op.SignatureKeyID()]
		if p == nil {
			return ErrInvalidSigningKey
		}

		n.incoming = append(n.incoming, p)
		p.outgoing = append(p.outgoing, n)
	}

	return nil
}

func (s *SignatureGraph) revoke(op *Operation, a *Action) error {
	// lookup the key the action refers to
	n, ok := s.keys[a.KID]

	// if the key does not exist, then the revocation is invalid
	if !ok {
		return ErrKeyMissing
	}

	// if this is the first (root) operation, then key revocation is not permitted
	if op.Sequence == 0 {
		return ErrInvalidKeyRevocation
	}

	// if the key has been revoked, then fail
	if n.ra != 0 {
		return ErrKeyAlreadyRevoked
	}

	n.ra = a.EffectiveFrom

	sk, ok := s.keys[op.SignatureKeyID()]
	if !ok {
		return ErrInvalidSigningKey
	}

	if sk.typ == TypeRecoveryKey {
		// if the signing key was a recovery key, then nuke all existing keys
		s.root.ra = a.EffectiveFrom

		for _, cn := range s.root.collect() {
			if cn.ra == 0 {
				cn.ra = a.EffectiveFrom
			}
		}
	} else {
		// revoke all child keys created after the revocation takes effect
		for _, cn := range n.collect() {
			if cn.ca < a.EffectiveFrom {
				n.ra = a.EffectiveFrom
			}
		}
	}

	return nil
}

// Graphviz outputs the signature graph in graphviz dot format
func (s *SignatureGraph) Graphviz() string {
	var output []string

	output = append(output, "digraph G {")

	// insert a blank element to represent the account being created
	s.gv(&output, &Node{kid: "GENESIS"}, s.root)

	output = append(output, "}")

	return strings.Join(output, "\n")
}

func (s *SignatureGraph) gv(output *[]string, p, n *Node) {
	(*output) = append((*output), fmt.Sprintf("  \"%s [type=%s active=%t]\" -> \"%s [type=%s active=%t]\"", p.kid, p.typ, p.ra == 0, n.kid, n.typ, n.ra == 0))

	for _, e := range n.outgoing {
		s.gv(output, n, e)
	}
}
