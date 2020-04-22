package transport

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/selfid-net/self-go-sdk/pkg/pqueue"
	"github.com/selfid-net/self-go-sdk/pkg/protos/msgproto"
	"github.com/gogo/protobuf/proto"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ed25519"
)

const (
	priorityClose = iota
	priorityPing
	priorityNotification
	priorityACL
	priorityMessage
)

type (
	sigclose bool
	sigping  bool
)

// WebsocketConfig configuration for connecting to a websocket
type WebsocketConfig struct {
	MessagingURL string
	SelfID       string
	DeviceID     string
	PrivateKey   ed25519.PrivateKey
	TCPDeadline  time.Duration
	InboxSize    int
	OnConnect    func()
	OnDisconnect func()
	messagingID  string
}

func (c *WebsocketConfig) load() {
	c.messagingID = fmt.Sprintf(
		"%s:%s",
		c.SelfID,
		c.DeviceID,
	)
}

// Websocket websocket client for self messaging
type Websocket struct {
	config    WebsocketConfig
	ws        *websocket.Conn
	queue     *pqueue.Queue
	inbox     chan proto.Message
	responses sync.Map
	closed    int32
}

type event struct {
	id   string
	data []byte
	err  chan error
}

// NewWebsocket creates a new websocket connection
func NewWebsocket(config WebsocketConfig) (*Websocket, error) {
	config.load()

	c := Websocket{
		config:    config,
		queue:     pqueue.New(5),
		inbox:     make(chan proto.Message, config.InboxSize),
		responses: sync.Map{},
		closed:    1,
	}

	return &c, c.connect()
}

// Send send a message to a given recipient. recipient is a combination of "selfID:deviceID"
func (c *Websocket) Send(recipients []string, data []byte) error {
	for _, r := range recipients {
		id := uuid.New().String()

		m, err := proto.Marshal(&msgproto.Message{
			Id:         id,
			Sender:     c.config.messagingID,
			Recipient:  r,
			Ciphertext: data,
		})

		if err != nil {
			return err
		}

		e := event{
			id:   id,
			data: m,
			err:  make(chan error, 1),
		}

		c.queue.Push(priorityMessage, &e)

		err = <-e.err
		if err != nil {
			return err
		}
	}

	return nil
}

// Receive receive a message
func (c *Websocket) Receive() (string, []byte, error) {
	e := <-c.inbox

	m, ok := e.(*msgproto.Message)
	if !ok {
		return "", nil, errors.New("received unknown message")
	}

	fmt.Println(string(m.Ciphertext))

	return m.Sender, m.Ciphertext, nil
}

// Command sends a command to the messaging server to be fulfilled
func (c *Websocket) Command(command string, payload []byte) ([]byte, error) {
	var cmd proto.Message

	id := uuid.New().String()

	switch command {
	case "acl.list":
		cmd = &msgproto.AccessControlList{
			Id:      id,
			Type:    msgproto.MsgType_ACL,
			Command: msgproto.ACLCommand_LIST,
		}
	case "acl.permit":
		cmd = &msgproto.AccessControlList{
			Id:      id,
			Type:    msgproto.MsgType_ACL,
			Command: msgproto.ACLCommand_PERMIT,
			Payload: payload,
		}
	case "acl.revoke":
		cmd = &msgproto.AccessControlList{
			Id:      id,
			Type:    msgproto.MsgType_ACL,
			Command: msgproto.ACLCommand_REVOKE,
			Payload: payload,
		}
	}

	req, err := proto.Marshal(cmd)
	if err != nil {
		return nil, err
	}

	e := event{
		id:   id,
		data: req,
		err:  make(chan error, 1),
	}

	c.queue.Push(priorityNotification, &e)

	return e.data, <-e.err
}

// Close closes the messaging clients persistent connection
func (c *Websocket) Close() error {
	return nil
}

func (c *Websocket) pongHandler(string) error {
	deadline := time.Now().Add(c.config.TCPDeadline)
	c.ws.SetReadDeadline(deadline)
	return nil
}

func (c *Websocket) connect() error {
	atomic.StoreInt32(&c.closed, 0)

	token, err := GenerateToken(c.config.SelfID, c.config.PrivateKey)
	if err != nil {
		return err
	}

	ws, _, err := websocket.DefaultDialer.Dial(c.config.MessagingURL, nil)
	if err != nil {
		return err
	}

	c.ws = ws

	ws.SetPongHandler(c.pongHandler)

	auth := msgproto.Auth{
		Id:     uuid.New().String(),
		Type:   msgproto.MsgType_AUTH,
		Token:  token,
		Device: c.config.DeviceID,
	}

	data, err := proto.Marshal(&auth)
	if err != nil {
		return err
	}

	err = c.ws.WriteMessage(websocket.BinaryMessage, data)
	if err != nil {
		return err
	}

	ws.SetReadDeadline(time.Now().Add(c.config.TCPDeadline))
	_, data, err = c.ws.ReadMessage()
	if err != nil {
		return err
	}

	var resp msgproto.Notification

	err = proto.Unmarshal(data, &resp)
	if err != nil {
		return err
	}

	switch resp.Type {
	case msgproto.MsgType_ACK:
	case msgproto.MsgType_ERR:
		return errors.New(resp.Error)
	default:
		return errors.New("unknown authentication response")
	}

	go c.reader()
	go c.writer()
	go c.ping()

	if c.config.OnConnect != nil {
		c.config.OnConnect()
	}

	return nil
}

func (c *Websocket) reader() {
	var hdr msgproto.Header

	for {
		if c.isClosed() {
			return
		}

		_, data, err := c.ws.ReadMessage()
		if err != nil {
			c.reconnect(err)
			return
		}

		err = proto.Unmarshal(data, &hdr)
		if err != nil {
			continue
		}

		var m proto.Message

		switch hdr.Type {
		case msgproto.MsgType_MSG:
			m = &msgproto.Message{}
		case msgproto.MsgType_ACL:
			m = &msgproto.AccessControlList{}
		case msgproto.MsgType_ACK, msgproto.MsgType_ERR:
			m = &msgproto.Notification{}
		}

		err = proto.Unmarshal(data, m)
		if err != nil {
			continue
		}

		switch hdr.Type {
		case msgproto.MsgType_ACK, msgproto.MsgType_ERR:
			n := m.(*msgproto.Notification)

			pch, ok := c.responses.Load(n.Id)
			if !ok {
				return
			}

			c.responses.Delete(n.Id)

			if n.Type == msgproto.MsgType_ACK {
				pch.(*event).err <- nil
			}

			pch.(*event).err <- errors.New(n.Error)
		case msgproto.MsgType_ACL:
			a := m.(*msgproto.AccessControlList)

			pch, ok := c.responses.Load(a.Id)
			if !ok {
				return
			}

			c.responses.Delete(a.Id)

			ev := pch.(*event)
			ev.data = a.Payload
			ev.err <- nil
		case msgproto.MsgType_MSG:
			c.inbox <- m
		}
	}
}

func (c *Websocket) writer() {
	var err error

	for {
		p, e := c.queue.PopWithPrioriry()

		switch p {
		case priorityClose:
			return
		case priorityPing:
			err = c.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(c.config.TCPDeadline))
		case priorityNotification, priorityMessage:
			ev := e.(*event)
			c.responses.Store(ev.id, ev)

			err = c.ws.WriteMessage(websocket.BinaryMessage, ev.data)
			if err != nil {
				ev.err <- err
				continue
			}
		}

		if err != nil {
			c.close()
		}
	}
}

func (c *Websocket) ping() {
	for {
		c.queue.Push(priorityPing, sigping(true))

		time.Sleep(c.config.TCPDeadline / 2)
	}
}

func (c *Websocket) reconnect(err error) {
	c.close()

	switch e := err.(type) {
	case net.Error:
		if !e.Timeout() {
			return
		}
	case *websocket.CloseError:
		if e.Code != websocket.CloseAbnormalClosure {
			return
		}
	}

	for i := 0; i < 20; i++ {
		err := c.connect()
		if err == nil {
			return
		}

		time.Sleep(c.config.TCPDeadline)
	}
}

func (c *Websocket) close() {
	if c.isClosed() {
		return
	}

	atomic.StoreInt32(&(c.closed), int32(1))

	if c.config.OnDisconnect != nil {
		c.config.OnDisconnect()
	}

	c.queue.Push(priorityClose, sigclose(true))

	time.Sleep(time.Millisecond * 10)
	c.ws.Close()
}

func (c *Websocket) isClosed() bool {
	return atomic.LoadInt32(&c.closed) == 1
}
