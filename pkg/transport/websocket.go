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

	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/joinself/self-go-sdk/pkg/pqueue"
	"github.com/joinself/self-go-sdk/pkg/protos/msgprotov2"
	"golang.org/x/crypto/ed25519"
)

const (
	priorityClose = iota
	priorityPong
	priorityNotification
	priorityACL
	priorityMessage
)

// ErrChannelClosed returned when the websocket connection is shut down manually
var ErrChannelClosed = errors.New("channel closed")

type (
	sigclose bool
	sigpong  bool
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
	inbox     chan *msgprotov2.Message
	responses sync.Map
	offset    int64
	ofd       *os.File
	closed    int32
	shutdown  int32
	pool      sync.Pool
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
		inbox:     make(chan *msgprotov2.Message, config.InboxSize),
		responses: sync.Map{},
		offset:    offset,
		ofd:       fd,
		closed:    1,
		pool: sync.Pool{
			New: func() interface{} {
				return flatbuffers.NewBuilder(1024)
			},
		},
	}

	return &c, c.connect()
}

// Send send a message to given recipients. recipient is a combination of "selfID:deviceID"
func (c *Websocket) Send(recipients []string, data []byte) error {
	b := c.pool.Get().(*flatbuffers.Builder)
	defer c.pool.Put(b)

	for _, r := range recipients {
		id := uuid.New().String()

		// reset the flatbuffer builder's internal buffer
		b.Reset()

		mid := b.CreateString(id)
		msd := b.CreateString(c.config.messagingID)
		mrp := b.CreateString(r)
		mct := b.CreateByteVector(data)

		msgprotov2.MessageStart(b)
		msgprotov2.MessageAddId(b, mid)
		msgprotov2.MessageAddMsgtype(b, msgprotov2.MsgTypeMSG)
		msgprotov2.MessageAddSender(b, msd)
		msgprotov2.MessageAddRecipient(b, mrp)
		msgprotov2.MessageAddMetadata(b, msgprotov2.CreateMetadata(
			b,
			0,
			0,
		))

		msgprotov2.MessageAddCiphertext(b, mct)
		msg := msgprotov2.MessageEnd(b)

		b.Finish(msg)

		fb := b.FinishedBytes()
		m := make([]byte, len(fb))
		copy(m, fb)

		e := event{
			id:   id,
			data: m,
			err:  make(chan error, 1),
		}

		c.queue.Push(priorityMessage, &e)

		err := <-e.err
		if err != nil {
			return err
		}
	}

	return nil
}

// SendAsync send a message to given recipients with a callback to handle the server response
func (c *Websocket) SendAsync(recipients []string, data []byte, callback func(err error)) {
	b := c.pool.Get().(*flatbuffers.Builder)
	defer c.pool.Put(b)

	for _, r := range recipients {
		id := uuid.New().String()

		// reset the flatbuffer builder's internal buffer
		b.Reset()

		mid := b.CreateString(id)
		msd := b.CreateString(c.config.messagingID)
		mrp := b.CreateString(r)
		mct := b.CreateByteVector(data)

		msgprotov2.MessageStart(b)
		msgprotov2.MessageAddId(b, mid)
		msgprotov2.MessageAddMsgtype(b, msgprotov2.MsgTypeMSG)
		msgprotov2.MessageAddSender(b, msd)
		msgprotov2.MessageAddRecipient(b, mrp)
		msgprotov2.MessageAddMetadata(b, msgprotov2.CreateMetadata(
			b,
			0,
			0,
		))

		msgprotov2.MessageAddCiphertext(b, mct)
		msg := msgprotov2.MessageEnd(b)

		b.Finish(msg)

		fb := b.FinishedBytes()
		m := make([]byte, len(fb))
		copy(m, fb)

		e := event{
			id:   id,
			data: m,
			cb:   callback,
		}

		c.queue.Push(priorityMessage, &e)
	}
}

// SendAsync send a message with a given id to a single recipient, with a callback to handle the server response
func (c *Websocket) SendAsyncWithID(id, recipient string, data []byte, callback func(err error)) {
	b := c.pool.Get().(*flatbuffers.Builder)
	defer c.pool.Put(b)

	// reset the flatbuffer builder's internal buffer
	b.Reset()

	mid := b.CreateString(id)
	msd := b.CreateString(c.config.messagingID)
	mrp := b.CreateString(recipient)
	mct := b.CreateByteVector(data)

	msgprotov2.MessageStart(b)
	msgprotov2.MessageAddId(b, mid)
	msgprotov2.MessageAddMsgtype(b, msgprotov2.MsgTypeMSG)
	msgprotov2.MessageAddSender(b, msd)
	msgprotov2.MessageAddRecipient(b, mrp)
	msgprotov2.MessageAddMetadata(b, msgprotov2.CreateMetadata(
		b,
		0,
		0,
	))

	msgprotov2.MessageAddCiphertext(b, mct)
	msg := msgprotov2.MessageEnd(b)

	b.Finish(msg)

	fb := b.FinishedBytes()
	m := make([]byte, len(fb))
	copy(m, fb)

	e := event{
		id:   id,
		data: m,
		cb:   callback,
	}

	c.queue.Push(priorityMessage, &e)
}

// Receive receive a message
func (c *Websocket) Receive() (string, []byte, error) {
	m, ok := <-c.inbox
	if !ok {
		return "", nil, ErrChannelClosed
	}

	return string(m.Sender()), m.CiphertextBytes(), nil
}

// Command sends a command to the messaging server to be fulfilled
func (c *Websocket) Command(command string, payload []byte) ([]byte, error) {
	b := c.pool.Get().(*flatbuffers.Builder)
	defer c.pool.Put(b)

	id := uuid.New().String()

	b.Reset()

	aid := b.CreateByteString([]byte(id))
	apl := b.CreateByteVector(payload)

	msgprotov2.ACLStart(b)
	msgprotov2.ACLAddMsgtype(b, msgprotov2.MsgTypeACL)
	msgprotov2.ACLAddId(b, aid)

	switch command {
	case "acl.list":
		msgprotov2.ACLAddCommand(b, msgprotov2.ACLCommandLIST)
	case "acl.permit":
		msgprotov2.ACLAddCommand(b, msgprotov2.ACLCommandPERMIT)
		msgprotov2.ACLAddPayload(b, apl)
	case "acl.revoke":
		msgprotov2.ACLAddCommand(b, msgprotov2.ACLCommandREVOKE)
		msgprotov2.ACLAddPayload(b, apl)
	}

	acl := msgprotov2.ACLEnd(b)

	b.Finish(acl)

	e := event{
		id:   id,
		data: b.FinishedBytes(),
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

func (c *Websocket) pingHandler(string) error {
	if c.config.OnPing != nil {
		c.config.OnPing()
	}

	deadline := time.Now().Add(c.config.TCPDeadline)

	c.queue.Push(priorityPong, sigpong(true))

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

	ws.SetPingHandler(c.pingHandler)

	c.ws = ws

	b := c.pool.Get().(*flatbuffers.Builder)
	defer c.pool.Put(b)

	b.Reset()

	aid := b.CreateString(uuid.New().String())
	aat := b.CreateString(token)
	adv := b.CreateString(c.config.DeviceID)

	msgprotov2.AuthStart(b)
	msgprotov2.AuthAddId(b, aid)
	msgprotov2.AuthAddMsgtype(b, msgprotov2.MsgTypeAUTH)
	msgprotov2.AuthAddDevice(b, adv)
	msgprotov2.AuthAddOffset(b, c.offset)
	msgprotov2.AuthAddToken(b, aat)
	auth := msgprotov2.AuthEnd(b)

	b.Finish(auth)

	err = c.ws.WriteMessage(websocket.BinaryMessage, b.FinishedBytes())
	if err != nil {
		return err
	}

	c.ws.SetReadDeadline(time.Now().Add(c.config.TCPDeadline))
	_, data, err := c.ws.ReadMessage()
	if err != nil {
		return err
	}

	resp := msgprotov2.GetRootAsNotification(data, 0)

	switch resp.Msgtype() {
	case msgprotov2.MsgTypeACK:
	case msgprotov2.MsgTypeERR:
		return errors.New(string(resp.Error()))
	default:
		return errors.New("unknown authentication response")
	}

	connected = true

	go c.reader()
	go c.writer()

	if c.config.OnConnect != nil {
		c.config.OnConnect()
	}

	return nil
}

func (c *Websocket) reader() {
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

		hdr := msgprotov2.GetRootAsHeader(data, 0)

		switch hdr.Msgtype() {
		case msgprotov2.MsgTypeACK, msgprotov2.MsgTypeERR:
			n := msgprotov2.GetRootAsNotification(data, 0)

			pch, ok := c.responses.Load(string(n.Id()))
			if !ok {
				continue
			}

			c.responses.Delete(string(n.Id()))

			var rerr error

			if n.Msgtype() == msgprotov2.MsgTypeERR {
				rerr = errors.New(string(n.Error()))
			}

			rev := pch.(*event)

			if rev.cb != nil {
				rev.cb(rerr)
			} else {
				rev.err <- rerr
			}

		case msgprotov2.MsgTypeACL:
			a := msgprotov2.GetRootAsACL(data, 0)

			pch, ok := c.responses.Load(string(a.Id()))
			if !ok {
				continue
			}

			c.responses.Delete(string(a.Id()))

			ev := pch.(*event)
			ev.data = a.PayloadBytes()
			ev.err <- nil

		case msgprotov2.MsgTypeMSG:
			m := msgprotov2.GetRootAsMessage(data, 0)

			md := m.Metadata(nil)
			if md == nil {
				log.Fatal("message did not contain valid metadata")
			}

			c.offset = md.Offset()

			offsetData := []byte(fmt.Sprintf("%019d", c.offset))

			// TODO : flush this to disk every n seconds?
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
		case priorityPong:
			deadline := time.Now().Add(c.config.TCPDeadline)
			err = c.ws.WriteControl(websocket.PongMessage, nil, deadline)
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
