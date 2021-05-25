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

	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/joinself/self-go-sdk/pkg/ntp"
	"github.com/joinself/self-go-sdk/pkg/protos/msgprotov2"
	"github.com/square/go-jose"
	"golang.org/x/crypto/ed25519"
)

var token string
var sk ed25519.PrivateKey
var pk ed25519.PublicKey

type testmsgserver struct {
	s        *httptest.Server
	in       chan *msgprotov2.Message
	out      chan []byte
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

func wait(ch chan *msgprotov2.Message) (*msgprotov2.Message, error) {
	select {
	case msg := <-ch:
		return msg, nil
	case <-time.After(time.Millisecond * 100):
		return nil, errors.New("channel read timeout")
	}
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
	return newTestMessagingServerWithInbox(t, 1024)
}

func newTestMessagingServerWithInbox(t *testing.T, inboxSize int) *testmsgserver {
	s := testmsgserver{
		in:   make(chan *msgprotov2.Message, inboxSize),
		out:  make(chan []byte, 1024),
		stop: make(chan bool, 1),
	}

	m := http.NewServeMux()
	m.HandleFunc("/", s.testHandler)

	s.s = httptest.NewServer(m)
	s.endpoint = "ws" + strings.TrimPrefix(s.s.URL, "http")

	return &s
}

func errorMessage(id string, err error) []byte {
	b := flatbuffers.NewBuilder(1024)

	nid := b.CreateString(id)

	msgprotov2.NotificationStart(b)
	msgprotov2.NotificationAddMsgtype(b, msgprotov2.MsgTypeERR)
	msgprotov2.NotificationAddId(b, nid)
	n := msgprotov2.NotificationEnd(b)

	b.Finish(n)

	return b.FinishedBytes()
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

	wc.SetPongHandler(func(appData string) error {
		err := wc.SetReadDeadline(time.Now().Add(time.Second * 5))
		if err != nil {
			log.Println(err.Error())
		}

		return err
	})

	_, msg, err := wc.ReadMessage()
	if err != nil {
		panic(err)
	}

	req := msgprotov2.GetRootAsAuth(msg, 0)

	rt, err := jose.ParseSigned(string(req.Token()))
	if err != nil {
		panic(err)
	}

	payload, err := rt.Verify(pk)
	if err != nil {
		wc.WriteMessage(websocket.BinaryMessage, errorMessage(string(req.Id()), err))
		panic(err)
	}

	var claims map[string]interface{}

	err = json.Unmarshal(payload, &claims)
	if err != nil {
		wc.WriteMessage(websocket.BinaryMessage, errorMessage(string(req.Id()), err))
		panic(err)
	}

	_, ok := claims["iss"]
	if !ok {
		wc.WriteMessage(websocket.BinaryMessage, errorMessage(string(req.Id()), errors.New("invalid issuer")))
		panic("invalid issuer")
	}

	b := flatbuffers.NewBuilder(1024)

	nid := b.CreateByteString(req.Id())

	msgprotov2.NotificationStart(b)
	msgprotov2.NotificationAddMsgtype(b, msgprotov2.MsgTypeACK)
	msgprotov2.NotificationAddId(b, nid)
	n := msgprotov2.NotificationEnd(b)

	b.Finish(n)

	wc.WriteMessage(websocket.BinaryMessage, b.FinishedBytes())

	go func() {
		for {
			_, data, err := wc.ReadMessage()
			if err != nil {
				return
			}

			h := msgprotov2.GetRootAsHeader(data, 0)

			b := flatbuffers.NewBuilder(1024)

			nid := b.CreateByteString(h.Id())

			msgprotov2.NotificationStart(b)
			msgprotov2.NotificationAddMsgtype(b, msgprotov2.MsgTypeACK)
			msgprotov2.NotificationAddId(b, nid)
			n := msgprotov2.NotificationEnd(b)

			b.Finish(n)

			t.out <- b.FinishedBytes()

			if h.Msgtype() == msgprotov2.MsgTypeMSG {
				m := msgprotov2.GetRootAsMessage(data, 0)

				md := m.Metadata(nil)
				if md == nil {
					panic("metadata is nil")
				}

				md.MutateOffset(atomic.AddInt64(&offset, 1))

				t.in <- m
			}
		}
	}()

	go func() {
		for {
			/*
				var data []byte
				var err error
			*/

			data := <-t.out

			/*
				switch v := e.(type) {
				case *msgprotov1.Message:
					v.Offset = atomic.AddInt64(&offset, 1)
					data, err = proto.Marshal(v)
				case *msgprotov1.Notification:
					data, err = proto.Marshal(v)
				}

				if err != nil {
					log.Println(err)
					return
				}
			*/

			t.mu.Lock()
			err = wc.SetWriteDeadline(time.Now().Add(time.Millisecond * 100))
			if err != nil {
				t.mu.Unlock()
				log.Println(err)
				return
			}

			err = wc.WriteMessage(websocket.BinaryMessage, data)
			t.mu.Unlock()

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
