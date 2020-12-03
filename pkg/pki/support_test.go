// Copyright 2020 Self Group Ltd. All Rights Reserved.

package pki

import (
	"errors"
	"strings"
)

var cts = strings.Contains

type testPKITransport struct {
	path    string
	payload []byte
}

func newTestPKITransport(path string, payload []byte) *testPKITransport {
	return &testPKITransport{path, payload}
}

func (t *testPKITransport) Get(path string) ([]byte, error) {
	if path != t.path {
		return nil, errors.New("not found")
	}

	if cts(path, "unknown") {
		return nil, errors.New("identity does not exist")
	}

	return t.payload, nil
}

func (t *testPKITransport) Post(path, contentType string, data []byte) ([]byte, error) {
	if path != t.path {
		return nil, errors.New("not found")
	}

	if cts(path, "unknown") {
		return nil, errors.New("identity does not exist")
	}

	return data, nil
}
