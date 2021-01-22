// Copyright 2020 Self Group Ltd. All Rights Reserved.

package messaging

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMessagingSend(t *testing.T) {
	ws := newTestWebsocket()
	cr := newTestCrypto()

	cfg := Config{
		SelfID:    "test",
		DeviceID:  "1",
		Transport: ws,
		Crypto:    cr,
	}

	c, err := New(cfg)
	require.Nil(t, err)

	err = c.Send([]string{"alice:1"}, []byte("test"))
	require.Nil(t, err)

	e := <-ws.out
	require.NotNil(t, e)
	assert.Equal(t, "alice:1", e.recipient)
	assert.Equal(t, []byte("dGVzdA"), e.data)

	err = c.Send([]string{"alice:1", "bob:1", "charlie:1"}, []byte("test"))
	require.Nil(t, err)

	for _, r := range []string{"alice:1", "bob:1", "charlie:1"} {
		e := <-ws.out
		require.NotNil(t, e)
		assert.Equal(t, r, e.recipient)
		assert.Equal(t, []byte("dGVzdA"), e.data)
	}
}

func TestMessagingRequest(t *testing.T) {
	ws := newTestWebsocket()
	cr := newTestCrypto()

	cfg := Config{
		SelfID:    "test",
		DeviceID:  "1",
		Transport: ws,
		Crypto:    cr,
	}

	c, err := New(cfg)
	require.Nil(t, err)

	go func() {
		<-ws.out
		resp := []byte(`{"payload":"eyJjaWQiOiAiMSIsICJyZXNwIjogInRlc3QifQ"}`)
		ws.in <- &testEvent{sender: "alice:1", data: []byte(decoder.EncodeToString(resp))}
	}()

	_, response, err := c.Request([]string{"alice:1"}, "1", []byte(`{"payload":"eyJjaWQiOiAiMSJ9"}`), 0)
	require.Nil(t, err)
	assert.NotNil(t, response)
}

func TestMessagingRegisterWait(t *testing.T) {
	ws := newTestWebsocket()
	cr := newTestCrypto()

	cfg := Config{
		SelfID:    "test",
		DeviceID:  "1",
		Transport: ws,
		Crypto:    cr,
	}

	c, err := New(cfg)
	require.Nil(t, err)

	_, _, err = c.Wait("1", time.Millisecond)
	require.NotNil(t, err)

	c.Register("2")

	resp := []byte(`{"payload":"eyJjaWQiOiAiMiJ9"}`)
	ws.in <- &testEvent{
		data: []byte(decoder.EncodeToString(resp)),
	}

	ch, _ := c.responses.Load("2")

	e := <-ch.(chan response)

	assert.NotNil(t, e)
	assert.Equal(t, resp, e.payload)

	c.Register("1")

	resp = []byte(`{"payload":"eyJjaWQiOiAiMSIsICJyZXNwIjogInRlc3QifQ"}`)
	ws.in <- &testEvent{sender: "alice:1", data: []byte(decoder.EncodeToString(resp))}

	_, r, err := c.Wait("1", time.Second)
	require.Nil(t, err)
	assert.Equal(t, resp, r)
}

func TestMessagingSubscribe(t *testing.T) {
	ws := newTestWebsocket()
	cr := newTestCrypto()

	cfg := Config{
		SelfID:    "test",
		DeviceID:  "1",
		Transport: ws,
		Crypto:    cr,
	}

	c, err := New(cfg)
	require.Nil(t, err)

	resp := make(chan *testEvent, 1)

	c.Subscribe("test", func(sender string, data []byte) {
		resp <- &testEvent{sender: sender, data: data}
	})

	req := []byte(`{"payload":"eyJ0eXAiOiJ0ZXN0In0"}`)
	ws.in <- &testEvent{sender: "alice:1", data: []byte(decoder.EncodeToString(req))}

	r := <-resp

	assert.NotNil(t, r)
	assert.Equal(t, "alice:1", r.sender)
	assert.Equal(t, req, r.data)
}

func TestMessagingClose(t *testing.T) {
	ws := newTestWebsocket()
	cr := newTestCrypto()

	cfg := Config{
		SelfID:    "test",
		DeviceID:  "1",
		Transport: ws,
		Crypto:    cr,
	}

	c, err := New(cfg)
	require.Nil(t, err)

	time.Sleep(time.Millisecond * 100)

	close(ws.in)

	err = c.Close()
	require.Nil(t, err)
}
