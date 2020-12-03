// Copyright 2020 Self Group Ltd. All Rights Reserved.

package siggraph

// JWS stores a single signature jws object
type JWS struct {
	Payload   string `json:"payload"`
	Protected string `json:"protected"`
	Signature string `json:"signature"`
}
