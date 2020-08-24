package siggraph

import "encoding/base64"

var (
	// TypeDeviceKey the type of key the action relates to
	TypeDeviceKey = "device.key"
	// TypeRecoveryKey the type of key the action relates to
	TypeRecoveryKey = "recovery.key"

	// ActionKeyAdd adds a key to the signature graph
	ActionKeyAdd = "key.add"
	// ActionKeyRevoke revokes a key from the signature graph
	ActionKeyRevoke = "key.revoke"
)

// Action defines configuration for an action to perform on the identities signature graph
type Action struct {
	KID           string `json:"kid"`           // the unique id of the key the action relates to
	DID           string `json:"did,omitempty"` // the id of the device the key relates to
	Type          string `json:"type"`          // type of key [device.key, recovery.key]
	Action        string `json:"action"`        // action to perform [key.add, key.revoke]
	EffectiveFrom int64  `json:"from"`          // determines the time at which the action should be valid from. This could be set in the past when wishing to revoke a key from a given time onward
	Key           string `json:"key,omitempty"` // the ed25519 public key (base64 url encoded)
}

// Validate validates an actions parameters
func (a *Action) Validate() error {
	if a.KID == "" {
		return ErrInvalidActionKeyID
	}

	if a.Type != TypeDeviceKey && a.Type != TypeRecoveryKey {
		return ErrUnknownActionType
	}

	if a.Action != ActionKeyAdd && a.Action != ActionKeyRevoke {
		return ErrUnknownAction
	}

	if a.Action == ActionKeyAdd && a.Key == "" {
		return ErrInvalidActionKey
	}

	if a.Action == ActionKeyAdd && a.Type == TypeDeviceKey && a.DID == "" {
		return ErrInvalidActionDID
	}

	if a.EffectiveFrom < 0 {
		return ErrInvalidActionEffectiveFromTime
	}

	if a.Action == ActionKeyAdd {
		data, err := base64.RawURLEncoding.DecodeString(a.Key)
		if err != nil {
			return ErrInvalidPublicKeyEncoding
		}

		if len(data) != 32 {
			return ErrInvalidPublicKeyLength
		}
	}

	return nil
}
