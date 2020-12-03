// Copyright 2020 Self Group Ltd. All Rights Reserved.

package transport

import (
	"bytes"
	"io/ioutil"
	"net/http"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"testing"
)

func TestRestAuthSuccess(t *testing.T) {
	s := newTestAPIServer(t)
	defer s.s.Close()

	s.handler = func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "ok"}`))
	}

	cfg := RestConfig{
		SelfID:     "test",
		PrivateKey: sk,
		APIURL:     s.endpoint,
		Client:     http.DefaultClient,
	}

	c, err := NewRest(cfg)
	require.Nil(t, err)

	resp, err := c.Get("/")
	require.Nil(t, err)
	assert.Equal(t, []byte(`{"status": "ok"}`), resp)
}

func TestRestAuthFailure(t *testing.T) {
	s := newTestAPIServer(t)
	defer s.s.Close()

	s.handler = func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error": "unauthorized"}`, http.StatusForbidden)
	}

	cfg := RestConfig{
		SelfID:     "test",
		PrivateKey: sk,
		APIURL:     s.endpoint,
		Client:     http.DefaultClient,
	}

	c, err := NewRest(cfg)
	require.Nil(t, err)

	_, err = c.Get("/")
	require.NotNil(t, err)
}

func TestRestGetSuccess(t *testing.T) {
	s := newTestAPIServer(t)
	defer s.s.Close()

	s.handler = func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "ok"}`))
	}

	cfg := RestConfig{
		SelfID:     "test",
		PrivateKey: sk,
		APIURL:     s.endpoint,
		Client:     http.DefaultClient,
	}

	c, err := NewRest(cfg)
	require.Nil(t, err)

	resp, err := c.Get("/")
	require.Nil(t, err)
	assert.Equal(t, []byte(`{"status": "ok"}`), resp)
}

func TestRestGetFailure(t *testing.T) {
	s := newTestAPIServer(t)
	defer s.s.Close()

	s.handler = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() == "/badpath" {
			http.Error(w, `{"error": "not found"}`, http.StatusNotFound)
		}
	}

	cfg := RestConfig{
		SelfID:     "test",
		PrivateKey: sk,
		APIURL:     s.endpoint,
		Client:     http.DefaultClient,
	}

	c, err := NewRest(cfg)
	require.Nil(t, err)

	_, err = c.Get("/badpath")
	require.NotNil(t, err)
}

func TestRestPostSuccess(t *testing.T) {
	s := newTestAPIServer(t)
	defer s.s.Close()

	s.handler = func(w http.ResponseWriter, r *http.Request) {
		payload, err := ioutil.ReadAll(r.Body)
		require.Nil(t, err)
		assert.Equal(t, "encoding/json", r.Header.Get("Content-Type"))
		assert.Equal(t, []byte(`{"test": "payload"}`), payload)
		w.Write([]byte(`{"id": "test", "test": "payload"}`))
	}

	cfg := RestConfig{
		SelfID:     "test",
		PrivateKey: sk,
		APIURL:     s.endpoint,
		Client:     http.DefaultClient,
	}

	c, err := NewRest(cfg)
	require.Nil(t, err)

	resp, err := c.Post("/", "encoding/json", []byte(`{"test": "payload"}`))
	require.Nil(t, err)
	assert.Equal(t, []byte(`{"id": "test", "test": "payload"}`), resp)
}

func TestRestPostFailure(t *testing.T) {
	s := newTestAPIServer(t)
	defer s.s.Close()

	s.handler = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() == "/badpath" {
			http.Error(w, `{"error": "not found"}`, http.StatusNotFound)
			return
		}

		payload, err := ioutil.ReadAll(r.Body)
		require.Nil(t, err)

		if !bytes.Equal(payload, []byte(`{"test": "payload"}`)) {
			http.Error(w, `{"error": "not found"}`, http.StatusNotFound)
		}
	}

	cfg := RestConfig{
		SelfID:     "test",
		PrivateKey: sk,
		APIURL:     s.endpoint,
		Client:     http.DefaultClient,
	}

	c, err := NewRest(cfg)
	require.Nil(t, err)

	_, err = c.Post("/badpath", "encoding/json", []byte(`{"test": "payload"}`))
	require.NotNil(t, err)

	_, err = c.Post("/", "encoding/json", []byte(`bad payload`))
	require.NotNil(t, err)
}

func TestRestPutSuccess(t *testing.T) {
	s := newTestAPIServer(t)
	defer s.s.Close()

	s.handler = func(w http.ResponseWriter, r *http.Request) {
		payload, err := ioutil.ReadAll(r.Body)
		require.Nil(t, err)
		assert.Equal(t, "encoding/json", r.Header.Get("Content-Type"))
		assert.Equal(t, []byte(`{"test": "payload"}`), payload)
		w.Write([]byte(`{"id": "test", "test": "payload"}`))
	}

	cfg := RestConfig{
		SelfID:     "test",
		PrivateKey: sk,
		APIURL:     s.endpoint,
		Client:     http.DefaultClient,
	}

	c, err := NewRest(cfg)
	require.Nil(t, err)

	resp, err := c.Put("/", "encoding/json", []byte(`{"test": "payload"}`))
	require.Nil(t, err)
	assert.Equal(t, []byte(`{"id": "test", "test": "payload"}`), resp)
}

func TestRestPutFailure(t *testing.T) {
	s := newTestAPIServer(t)
	defer s.s.Close()

	s.handler = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() == "/badpath" {
			http.Error(w, `{"error": "not found"}`, http.StatusNotFound)
			return
		}

		payload, err := ioutil.ReadAll(r.Body)
		require.Nil(t, err)

		if !bytes.Equal(payload, []byte(`{"test": "payload"}`)) {
			http.Error(w, `{"error": "not found"}`, http.StatusNotFound)
		}
	}

	cfg := RestConfig{
		SelfID:     "test",
		PrivateKey: sk,
		APIURL:     s.endpoint,
		Client:     http.DefaultClient,
	}

	c, err := NewRest(cfg)
	require.Nil(t, err)

	_, err = c.Put("/badpath", "encoding/json", []byte(`{"test": "payload"}`))
	require.NotNil(t, err)

	_, err = c.Put("/", "encoding/json", []byte(`bad payload`))
	require.NotNil(t, err)
}
