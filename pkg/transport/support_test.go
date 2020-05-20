package transport

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/selfid-net/self-go-sdk/pkg/ntp"
	"github.com/selfid-net/self-go-sdk/pkg/protos/msgproto"
	"github.com/gogo/protobuf/proto"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/square/go-jose"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

var token string
var sk ed25519.PrivateKey
var pk ed25519.PublicKey

type testmsgserver struct {
	s        *httptest.Server
	in       chan msgproto.Message
	out      chan interface{}
	stop     chan bool
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

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: sk}, nil)
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
		in:   make(chan msgproto.Message),
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

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, nil)
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
	u := websocket.Upgrader{}

	wc, err := u.Upgrade(w, r, nil)
	if err != nil {
		panic(err)
	}

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
				var m msgproto.Message

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
				data, err = proto.Marshal(v)
			case *msgproto.Notification:
				data, err = proto.Marshal(v)
			}

			if err != nil {
				log.Println(err)
				return
			}

			wc.WriteMessage(websocket.BinaryMessage, data)
		}
	}()

	go func() {
		<-t.stop
		wc.SetReadDeadline(time.Now())
	}()
}