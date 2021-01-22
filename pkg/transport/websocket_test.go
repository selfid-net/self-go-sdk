// Copyright 2020 Self Group Ltd. All Rights Reserved.

package transport

import (
	"encoding/binary"
	"os"
	"testing"
	"time"

	"github.com/joinself/self-go-sdk/pkg/protos/msgproto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebsocketConnect(t *testing.T) {
	defer os.Remove("test:1.offset")

	s := newTestMessagingServer(t)
	defer s.s.Close()

	cfg := WebsocketConfig{
		SelfID:       "test",
		DeviceID:     "1",
		PrivateKey:   sk,
		MessagingURL: s.endpoint,
		TCPDeadline:  time.Millisecond * 100,
		InboxSize:    128,
	}

	c, err := NewWebsocket(cfg)
	require.Nil(t, err)
	require.Nil(t, c.Close())
}

func TestWebsocketReconnect(t *testing.T) {
	defer os.Remove("test:1.offset")

	s := newTestMessagingServer(t)
	defer s.s.Close()

	connected := make(chan bool, 1)
	disconnected := make(chan bool, 1)

	cfg := WebsocketConfig{
		SelfID:       "test",
		DeviceID:     "1",
		PrivateKey:   sk,
		MessagingURL: s.endpoint,
		TCPDeadline:  time.Second,
		InboxSize:    128,
		OnConnect: func() {
			connected <- true
		},
		OnDisconnect: func() {
			disconnected <- true
		},
	}

	c, err := NewWebsocket(cfg)
	require.Nil(t, err)
	defer c.Close()

	assert.True(t, <-connected)

	s.stop <- true

	assert.True(t, <-disconnected)

	s = newTestMessagingServer(t)
	defer s.s.Close()

	assert.True(t, <-connected)
}

func TestWebsocketSend(t *testing.T) {
	defer os.Remove("test:1.offset")

	s := newTestMessagingServer(t)
	defer s.s.Close()

	cfg := WebsocketConfig{
		SelfID:       "test",
		DeviceID:     "1",
		PrivateKey:   sk,
		MessagingURL: s.endpoint,
		TCPDeadline:  time.Millisecond * 100,
		InboxSize:    128,
	}

	c, err := NewWebsocket(cfg)
	require.Nil(t, err)
	defer c.Close()

	err = c.Send([]string{"alice:1"}, []byte("test"))
	require.Nil(t, err)

	msg, err := wait(s.in)
	require.Nil(t, err)

	assert.NotEmpty(t, msg.Id)
	assert.Equal(t, "test:1", msg.Sender)
	assert.Equal(t, "alice:1", msg.Recipient)
	assert.Equal(t, []byte("test"), msg.Ciphertext)
}

func TestWebsocketReceive(t *testing.T) {
	defer os.Remove("test:1.offset")

	s := newTestMessagingServer(t)
	defer s.s.Close()

	cfg := WebsocketConfig{
		SelfID:       "test",
		DeviceID:     "1",
		PrivateKey:   sk,
		MessagingURL: s.endpoint,
		TCPDeadline:  time.Millisecond * 100,
		InboxSize:    128,
	}

	c, err := NewWebsocket(cfg)
	require.Nil(t, err)
	defer c.Close()

	s.out <- &msgproto.Message{
		Id:         "test",
		Sender:     "alice:1",
		Recipient:  "test:1",
		Ciphertext: []byte("test"),
	}

	sender, m, err := c.Receive()
	require.Nil(t, err)

	assert.Equal(t, "alice:1", sender)
	assert.Equal(t, []byte("test"), m)
}

func TestOffsetFileConversion(t *testing.T) {
	defer os.Remove("test:1.offset")

	s := newTestMessagingServer(t)
	defer s.s.Close()

	// write the old offset format
	fd, err := os.Create("test:1.offset")
	require.Nil(t, err)

	offsetData := make([]byte, 8)

	binary.LittleEndian.PutUint64(offsetData, uint64(4719))

	_, err = fd.WriteAt(offsetData, 0)
	require.Nil(t, err)

	cfg := WebsocketConfig{
		SelfID:       "test",
		DeviceID:     "1",
		PrivateKey:   sk,
		MessagingURL: s.endpoint,
		TCPDeadline:  time.Millisecond * 100,
		InboxSize:    128,
	}

	c, err := NewWebsocket(cfg)
	require.Nil(t, err)
	defer c.Close()

	// check the offset has been loaded correctly
	assert.Equal(t, int64(4719), c.offset)
}

func TestWebsocketClose(t *testing.T) {
	defer os.Remove("test:1.offset")

	s := newTestMessagingServer(t)
	defer s.s.Close()

	cfg := WebsocketConfig{
		SelfID:       "test",
		DeviceID:     "1",
		PrivateKey:   sk,
		MessagingURL: s.endpoint,
		TCPDeadline:  time.Millisecond * 100,
		InboxSize:    10240,
	}

	c, err := NewWebsocket(cfg)
	require.Nil(t, err)

	// handle received messages
	go func() {
		for i := 0; i < 10000; i++ {
			c.Receive()
		}
	}()

	go func() {
		// send some messages
		for i := 0; i < 10000; i++ {
			s.out <- &msgproto.Message{
				Id:         "test",
				Sender:     "alice:1",
				Recipient:  "test:1",
				Ciphertext: []byte("test"),
			}
		}
	}()

	for len(c.inbox) < 1 {
		time.Sleep(time.Millisecond)
	}

	// close the connection
	c.Close()

	// check all messages have been processed
	assert.Len(t, c.inbox, 0)
}
