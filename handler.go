package selfsdk

import msgproto "github.com/selfid-net/self-messaging-proto"

// MessageHandler handles incoming messages
type MessageHandler func(m *msgproto.Message)
