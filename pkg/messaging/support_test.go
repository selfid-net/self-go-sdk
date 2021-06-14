// Copyright 2020 Self Group Ltd. All Rights Reserved.

package messaging

import (
	"errors"

	"github.com/joinself/self-go-sdk/pkg/transport"
)

type testEvent struct {
	sender    string
	recipient string
	data      []byte
}

type testWebsocket struct {
	in  chan *testEvent
	out chan *testEvent
}

func newTestWebsocket() *testWebsocket {
	return &testWebsocket{
		in:  make(chan *testEvent, 10),
		out: make(chan *testEvent, 10),
	}
}

func (c *testWebsocket) Send(recipients []string, data []byte) error {
	for _, r := range recipients {
		if r == "non-existent" {
			return errors.New("recipient does not exist")
		}
		c.out <- &testEvent{recipient: r, data: data}
	}
	return nil
}

func (c *testWebsocket) Receive() (string, []byte, error) {
	e, ok := <-c.in
	if !ok {
		return "", nil, transport.ErrChannelClosed
	}

	if e.recipient == "failure" {
		return "", nil, errors.New("transport failure")
	}
	return e.sender, e.data, nil
}

func (c *testWebsocket) Command(command string, payload []byte) ([]byte, error) {
	return []byte(`["*"]`), nil
}

func (c *testWebsocket) Close() error {
	return nil
}

type testCrypto struct{}

func newTestCrypto() *testCrypto {
	return &testCrypto{}
}

func (c *testCrypto) Encrypt(recipients []string, data []byte) ([]byte, error) {
	// fake encrypt the payload
	return []byte(decoder.EncodeToString(data)), nil
}

func (c *testCrypto) Decrypt(sender string, data []byte) ([]byte, error) {
	// fake decrypt the payload
	return decoder.DecodeString(string(data))
}
