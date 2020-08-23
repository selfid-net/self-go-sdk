package siggraph

import (
	"golang.org/x/crypto/ed25519"
)

// Node node
type Node struct {
	kid      string            // id of the key
	did      string            // id of the device
	typ      string            // type of key
	seq      int               // the sequence of the operatin the key was added
	ca       int64             // when the key was created at/valid from
	ra       int64             // when the key was revoked at
	pk       ed25519.PublicKey // the public key
	incoming []*Node           // all keys that signed this key when it was created
	outgoing []*Node           // all keys that this key has signed
}

// TODO : this might exceed stack size on large graphs, we should use a slice as a stack to avoid this issue

// collect collects all descendents of this node
func (n *Node) collect() []*Node {
	var nodes []*Node

	nodes = append(nodes, n.outgoing...)

	for _, c := range n.outgoing {
		nodes = append(nodes, c.collect()...)
	}

	return nodes
}
