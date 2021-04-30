// Copyright 2020 Self Group Ltd. All Rights Reserved.

package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/joinself/self-go-sdk/pkg/pqueue"
	"github.com/joinself/self-go-sdk/pkg/protos/msgproto"
	"golang.org/x/crypto/ed25519"
	"google.golang.org/protobuf/proto"
)

const (
	priorityClose = iota
	priorityPing
	priorityNotification
	priorityACL
	priorityMessage
)

// ErrChannelClosed returned when the websocket connection is shut down manually
var ErrChannelClosed = errors.New("channel closed")

type (
	sigclose bool
	sigping  bool
)

// WebsocketConfig configuration for connecting to a websocket
type WebsocketConfig struct {
	MessagingURL string
	StorageDir   string
	SelfID       string
	DeviceID     string
	KeyID        string
	PrivateKey   ed25519.PrivateKey
	TCPDeadline  time.Duration
	InboxSize    int
	OnConnect    func()
	OnDisconnect func(err error)
	OnPing       func()
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
	offset    int64
	ofd       *os.File
	closed    int32
	shutdown  int32
}

type event struct {
	id   string
	data []byte
	err  chan error
	cb   func(err error)
}

// NewWebsocket creates a new websocket connection
func NewWebsocket(config WebsocketConfig) (*Websocket, error) {
	config.load()

	if config.StorageDir != "" {
		err := os.MkdirAll(config.StorageDir, os.ModePerm)
		if err != nil {
			return nil, err
		}
	}

	offsetFile := filepath.Join(config.StorageDir, config.SelfID+":"+config.DeviceID+".offset")
	fd, err := os.OpenFile(offsetFile, os.O_CREATE|os.O_RDWR, 0766)
	if err != nil {
		return nil, err
	}

	stats, err := fd.Stat()
	if err != nil {
		return nil, err
	}

	var offset int64

	switch stats.Size() {
	case 0:
		err = fd.Truncate(19)
		if err != nil {
			return nil, err
		}

		_, err = fd.WriteAt([]byte("0000000000000000000"), 0)
		if err != nil {
			return nil, err
		}
	case 8:
		// convert the old offset format
		offsetData := make([]byte, 8)

		_, err = fd.Read(offsetData)
		if err != nil {
			return nil, err
		}

		err = fd.Truncate(19)
		if err != nil {
			return nil, err
		}

		offset = int64(binary.LittleEndian.Uint64(offsetData))
	case 19:
		offsetData := make([]byte, 19)

		_, err = fd.Read(offsetData)
		if err != nil {
			return nil, err
		}

		off, err := strconv.Atoi(string(offsetData))
		if err != nil {
			return nil, err
		}

		offset = int64(off)
	}

	c := Websocket{
		config:    config,
		queue:     pqueue.New(5),
		inbox:     make(chan proto.Message, config.InboxSize),
		responses: sync.Map{},
		offset:    offset,
		ofd:       fd,
		closed:    1,
	}

	return &c, c.connect()
}

// Send send a message to given recipients. recipient is a combination of "selfID:deviceID"
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

// SendAsync send a message to given recipients with a callback to handle the server response
func (c *Websocket) SendAsync(recipients []string, data []byte, callback func(err error)) {
	for _, r := range recipients {
		id := uuid.New().String()

		m, err := proto.Marshal(&msgproto.Message{
			Id:         id,
			Sender:     c.config.messagingID,
			Recipient:  r,
			Ciphertext: data,
		})

		if err != nil {
			callback(err)
			return
		}

		e := event{
			id:   id,
			data: m,
			cb:   callback,
		}

		c.queue.Push(priorityMessage, &e)
	}
}

// Receive receive a message
func (c *Websocket) Receive() (string, []byte, error) {
	e, ok := <-c.inbox
	if !ok {
		return "", nil, ErrChannelClosed
	}

	m, ok := e.(*msgproto.Message)
	if !ok {
		return "", nil, errors.New("received unknown message")
	}

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
	atomic.StoreInt32(&c.shutdown, 1)

	c.close(nil)

	// wait for subscribers to drain
	for len(c.inbox) > 0 {
		time.Sleep(time.Millisecond)
	}

	err := c.ofd.Sync()
	if err != nil {
		return err
	}

	return c.ofd.Close()
}

func (c *Websocket) pongHandler(string) error {
	if c.config.OnPing != nil {
		c.config.OnPing()
	}

	deadline := time.Now().Add(c.config.TCPDeadline)
	return c.ws.SetReadDeadline(deadline)
}

func (c *Websocket) connect() error {
	if !atomic.CompareAndSwapInt32(&c.closed, 1, 0) {
		return errors.New("could not connect")
	}

	var connected bool

	defer func(success *bool) {
		if !(*success) {
			// if it failed to reconnect, set the connection status to closed
			atomic.CompareAndSwapInt32(&c.closed, 0, 1)
		}
	}(&connected)

	token, err := GenerateToken(c.config.SelfID, c.config.KeyID, c.config.PrivateKey)
	if err != nil {
		return err
	}

	ws, _, err := websocket.DefaultDialer.Dial(c.config.MessagingURL, nil)
	if err != nil {
		return err
	}

	c.ws = ws

	auth := msgproto.Auth{
		Id:     uuid.New().String(),
		Type:   msgproto.MsgType_AUTH,
		Token:  token,
		Device: c.config.DeviceID,
		Offset: c.offset,
	}

	data, err := proto.Marshal(&auth)
	if err != nil {
		return err
	}

	err = c.ws.WriteMessage(websocket.BinaryMessage, data)
	if err != nil {
		return err
	}

	c.ws.SetReadDeadline(time.Now().Add(c.config.TCPDeadline))
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

	connected = true

	ws.SetPongHandler(c.pongHandler)

	go c.reader()
	go c.writer()

	if c.config.OnConnect != nil {
		c.config.OnConnect()
	}

	return nil
}

func (c *Websocket) reader() {
	var hdr msgproto.Header

	for {
		if c.isShutdown() {
			close(c.inbox)
		}

		if c.isClosed() {
			return
		}

		_, data, err := c.ws.ReadMessage()
		if err != nil {
			if c.isShutdown() {
				close(c.inbox)
			} else {
				c.reconnect(err)
			}
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
				continue
			}

			c.responses.Delete(n.Id)

			var rerr error

			if n.Type == msgproto.MsgType_ERR {
				rerr = errors.New(n.Error)
			}

			rev := pch.(*event)

			if rev.cb != nil {
				rev.cb(rerr)
			} else {
				rev.err <- rerr
			}
		case msgproto.MsgType_ACL:
			a := m.(*msgproto.AccessControlList)

			pch, ok := c.responses.Load(a.Id)
			if !ok {
				continue
			}

			c.responses.Delete(a.Id)

			ev := pch.(*event)
			ev.data = a.Payload
			ev.err <- nil
		case msgproto.MsgType_MSG:
			msg := m.(*msgproto.Message)

			c.offset = msg.Offset

			offsetData := []byte(fmt.Sprintf("%019d", c.offset))

			_, err = c.ofd.WriteAt(offsetData, 0)
			if err != nil {
				log.Fatal(err)
			}

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
				if ev.cb != nil {
					ev.cb(err)
				} else {
					ev.err <- err
				}
				continue
			}
		}

		if err != nil {
			c.close(err)
		}
	}
}

func (c *Websocket) reconnect(err error) {
	if !c.close(err) {
		return
	}

	switch e := err.(type) {
	case net.Error:
		if !e.Timeout() {
			log.Println("[websocket]", e)
		}
	case *websocket.CloseError:
		if e.Code != websocket.CloseAbnormalClosure {
			if e.Text != io.ErrUnexpectedEOF.Error() {
				return
			}
		}
	}

	for i := 0; i < 20; i++ {
		time.Sleep(c.config.TCPDeadline)

		err := c.connect()
		if err == nil {
			return
		}
	}
}

func (c *Websocket) close(err error) bool {
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return false
	}

	if c.config.OnDisconnect != nil {
		c.config.OnDisconnect(err)
	}

	c.queue.Push(priorityClose, sigclose(true))

	time.Sleep(time.Millisecond * 10)
	c.ws.Close()

	return true
}

func (c *Websocket) isClosed() bool {
	return atomic.LoadInt32(&c.closed) == 1
}

func (c *Websocket) isShutdown() bool {
	return atomic.LoadInt32(&c.shutdown) == 1
}
