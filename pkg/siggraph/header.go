// Copyright 2020 Self Group Ltd. All Rights Reserved.

package siggraph

// Header represents a jws header
type Header struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
}
