// Copyright 2020 Self Group Ltd. All Rights Reserved.

package transport

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/joinself/self-go-sdk/pkg/ntp"
	"github.com/joinself/self-go-sdk/pkg/protos/msgproto"
	"github.com/square/go-jose"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
	"google.golang.org/protobuf/proto"
)

var token string
var sk ed25519.PrivateKey
var pk ed25519.PublicKey

type testmsgserver struct {
	s        *httptest.Server
	in       chan msgproto.Message
	out      chan interface{}
	stop     chan bool
	mu       sync.Mutex
	endpoint string
}

type testapiserver struct {
	s        *httptest.Server
	endpoint string
	handler  func(w http.ResponseWriter, r *http.Request)
}

func init() {
	token, sk, pk = testToken("test")
}

func wait(ch chan msgproto.Message) (*msgproto.Message, error) {
	select {
	case msg := <-ch:
		return &msg, nil
	case <-time.After(time.Millisecond * 100):
		return nil, errors.New("channel read timeout")
	}
}

func newRequestMessage(t *testing.T, selfID, cid string) []byte {
	m, err := json.Marshal(map[string]string{
		"cid":     cid,
		"iss":     selfID,
		"message": "response",
	})

	require.Nil(t, err)

	opts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": "1",
		},
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: sk}, opts)
	require.Nil(t, err)

	signedPayload, err := signer.Sign(m)
	require.Nil(t, err)

	return []byte(signedPayload.FullSerialize())
}

func newTestAPIServer(t *testing.T) *testapiserver {
	var s testapiserver
	m := http.NewServeMux()
	m.HandleFunc("/", s.testHandler)
	s.s = httptest.NewServer(m)
	s.endpoint = s.s.URL

	return &s
}

func (s *testapiserver) testHandler(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")[7:]

	jwt, err := jose.ParseSigned(token)
	if err != nil {
		http.Error(w, `{"error": "unauthorized"}`, http.StatusForbidden)
		return
	}

	_, err = jwt.Verify(pk)
	if err != nil {
		http.Error(w, `{"error": "unauthorized"}`, http.StatusForbidden)
		return
	}

	if s.handler != nil {
		s.handler(w, r)
	}
}

func newTestMessagingServer(t *testing.T) *testmsgserver {
	s := testmsgserver{
		in:   make(chan msgproto.Message, 1024),
		out:  make(chan interface{}, 1024),
		stop: make(chan bool, 1),
	}

	m := http.NewServeMux()
	m.HandleFunc("/", s.testHandler)

	s.s = httptest.NewServer(m)
	s.endpoint = "ws" + strings.TrimPrefix(s.s.URL, "http")

	return &s
}

func errorMessage(id string, err error) []byte {
	m, err := proto.Marshal(&msgproto.Notification{Type: msgproto.MsgType_ERR, Id: id, Error: err.Error()})
	if err != nil {
		log.Println(err)
	}

	return m
}

func testToken(id string) (string, ed25519.PrivateKey, ed25519.PublicKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	claims, err := json.Marshal(map[string]interface{}{
		"jti": uuid.New().String(),
		"iss": id,
		"exp": ntp.TimeFunc().Add(time.Minute).Unix(),
	})

	if err != nil {
		panic(err)
	}

	opts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": "1",
		},
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, opts)
	if err != nil {
		panic(err)
	}

	signedPayload, err := signer.Sign(claims)
	if err != nil {
		panic(err)
	}

	token, err := signedPayload.CompactSerialize()
	if err != nil {
		panic(err)
	}

	return token, priv, pub
}

func (t *testmsgserver) testHandler(w http.ResponseWriter, r *http.Request) {
	var offset int64

	u := websocket.Upgrader{}

	wc, err := u.Upgrade(w, r, nil)
	if err != nil {
		panic(err)
	}

	wc.SetPingHandler(func(appData string) error {
		err := wc.SetReadDeadline(time.Now().Add(time.Second * 5))
		if err != nil {
			log.Println(err.Error())
		}

		t.mu.Lock()
		defer t.mu.Unlock()

		return wc.WriteControl(websocket.PongMessage, nil, time.Now().Add(time.Millisecond*100))
	})

	_, msg, err := wc.ReadMessage()
	if err != nil {
		panic(err)
	}

	var req msgproto.Auth

	err = proto.Unmarshal(msg, &req)
	if err != nil {
		wc.WriteMessage(websocket.BinaryMessage, errorMessage(req.Id, err))
		panic(err)
	}

	rt, err := jose.ParseSigned(req.Token)
	if err != nil {
		panic(err)
	}

	payload, err := rt.Verify(pk)
	if err != nil {
		wc.WriteMessage(websocket.BinaryMessage, errorMessage(req.Id, err))
		panic(err)
	}

	var claims map[string]interface{}

	err = json.Unmarshal(payload, &claims)
	if err != nil {
		wc.WriteMessage(websocket.BinaryMessage, errorMessage(req.Id, err))
		panic(err)
	}

	_, ok := claims["iss"]
	if !ok {
		wc.WriteMessage(websocket.BinaryMessage, errorMessage(req.Id, errors.New("invalid issuer")))
		panic("invalid issuer")
	}

	data, _ := proto.Marshal(&msgproto.Notification{Type: msgproto.MsgType_ACK, Id: req.Id})
	wc.WriteMessage(websocket.BinaryMessage, data)

	go func() {
		for {
			var h msgproto.Header

			_, data, err := wc.ReadMessage()
			if err != nil {
				return
			}

			err = proto.Unmarshal(data, &h)
			if err != nil {
				log.Println(err)
				return
			}

			t.out <- &msgproto.Notification{Type: msgproto.MsgType_ACK, Id: h.Id}

			if h.Type == msgproto.MsgType_MSG {
				m := msgproto.Message{
					Offset: atomic.AddInt64(&offset, 1),
				}

				err = proto.Unmarshal(data, &m)
				if err != nil {
					log.Println(err)
					return
				}

				t.in <- m
			}
		}
	}()

	go func() {
		for {
			var data []byte
			var err error

			e := <-t.out

			switch v := e.(type) {
			case *msgproto.Message:
				v.Offset = atomic.AddInt64(&offset, 1)
				data, err = proto.Marshal(v)
			case *msgproto.Notification:
				data, err = proto.Marshal(v)
			}

			if err != nil {
				log.Println(err)
				return
			}

			t.mu.Lock()
			err = wc.SetWriteDeadline(time.Now().Add(time.Millisecond * 100))
			if err != nil {
				log.Println(err)
				return
			}

			err = wc.WriteMessage(websocket.BinaryMessage, data)
			defer t.mu.Unlock()

			if err != nil {
				log.Println(err)
				return
			}
		}
	}()

	go func() {
		<-t.stop
		wc.SetReadDeadline(time.Now())
		wc.SetWriteDeadline(time.Now())
		wc.Close()
	}()
}
