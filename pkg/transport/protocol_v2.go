// Copyright 2020 Self Group Ltd. All Rights Reserved.

package transport

import (
	"errors"
	"sync"

	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/google/uuid"
	"github.com/joinself/self-go-sdk/pkg/protos/msgprotov2"
)

type encoderV2 struct {
	pool sync.Pool
}

func newEncoderV2() Encoder {
	return &encoderV2{
		pool: sync.Pool{
			New: func() interface{} {
				return flatbuffers.NewBuilder(1024)
			},
		},
	}
}

// MarshalAuth creates a protocol v2 auth message
func (e *encoderV2) MarshalAuth(device, token string, offset int64) ([]byte, error) {
	b := e.pool.Get().(*flatbuffers.Builder)
	b.Reset()

	aid := b.CreateString(uuid.New().String())
	aat := b.CreateString(token)
	adv := b.CreateString(device)

	msgprotov2.AuthStart(b)
	msgprotov2.AuthAddId(b, aid)
	msgprotov2.AuthAddMsgtype(b, msgprotov2.MsgTypeAUTH)
	msgprotov2.AuthAddDevice(b, adv)
	msgprotov2.AuthAddOffset(b, offset)
	msgprotov2.AuthAddToken(b, aat)
	auth := msgprotov2.AuthEnd(b)

	b.Finish(auth)

	fb := b.FinishedBytes()
	a := make([]byte, len(fb))
	copy(a, fb)

	e.pool.Put(b)

	return a, nil
}

// MarshalACL creates a protocol v2 acl command
func (e *encoderV2) MarshalACL(id, command string, payload []byte) ([]byte, error) {
	b := e.pool.Get().(*flatbuffers.Builder)
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

	fb := b.FinishedBytes()
	a := make([]byte, len(fb))
	copy(a, fb)

	e.pool.Put(b)

	return a, nil
}

// MarshalMessage creates a protocol v2 message
func (e *encoderV2) MarshalMessage(id, sender, recipient string, ciphertext []byte) ([]byte, error) {
	b := e.pool.Get().(*flatbuffers.Builder)

	// reset the flatbuffer builder's internal buffer
	b.Reset()

	mid := b.CreateString(id)
	msd := b.CreateString(sender)
	mrp := b.CreateString(recipient)
	mct := b.CreateByteVector(ciphertext)

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

	e.pool.Put(b)

	return m, nil
}

// UnmarshalHeader reads a protocol v2 header event
func (e *encoderV2) UnmarshalHeader(data []byte) (Header, error) {
	return msgprotov2.GetRootAsHeader(data, 0), nil
}

// UnmarshalNotification reads a protocol v2 notification event
func (e *encoderV2) UnmarshalNotification(data []byte) (Notification, error) {
	return msgprotov2.GetRootAsNotification(data, 0), nil
}

// UnmarshalMessage reads a protocol v2 message event
func (e *encoderV2) UnmarshalMessage(data []byte) (Message, int64, int64, error) {
	m := msgprotov2.GetRootAsMessage(data, 0)
	md := m.Metadata(nil)

	if md == nil {
		return nil, 0, 0, errors.New("invalid message metadata")
	}

	return m, md.Timestamp(), md.Offset(), nil
}

// UnmarshalACL reads a protocol v2 acl event
func (e *encoderV2) UnmarshalACL(data []byte) (ACL, error) {
	return msgprotov2.GetRootAsACL(data, 0), nil
}
