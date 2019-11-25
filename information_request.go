package selfsdk

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/selfid-net/self-go-sdk/messages"
	messaging "github.com/selfid-net/self-messaging-client"
)

// TypeInformationRequest the jws message type for an information request
const TypeInformationRequest = "identity_info_req"

// InformationRequest represents an information request
type InformationRequest struct {
	SelfID       string
	Fields       []messages.Field
	Description  string
	Intermediary string
	Expires      time.Duration
}

func (r *InformationRequest) build(cid, issuer string) ([]byte, error) {
	return json.Marshal(messages.IdentityInfoRequest{
		Typ:         TypeInformationRequest,
		Cid:         cid,
		Sub:         r.SelfID,
		Iss:         issuer,
		Iat:         messaging.TimeFunc().Format(time.RFC3339),
		Exp:         messaging.TimeFunc().Add(r.Expires).Format(time.RFC3339),
		Jti:         uuid.New().String(),
		Description: r.Description,
		Fields:      r.Fields,
	})
}

func (r *InformationRequest) recipient() string {
	if r.Intermediary != "" {
		return r.Intermediary
	}
	return r.SelfID
}
