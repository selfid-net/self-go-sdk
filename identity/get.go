// Copyright 2020 Self Group Ltd. All Rights Reserved.

package identity

import "encoding/json"

var (
	IdentityTypeIndividual = "individual"
	IdentityTypeApp        = "app"
)

// User identity -> Individual?
// Would be nice to have a way to refer/represent different classes of app or user identity
// so Identity can be either an [Individual, App, Asset], etc.

// Identity represents all information about a self identity
type Identity interface {
	SelfID() string
	Type() string
	History() []json.RawMessage
}

// replace this with whatever we decide for (individual, person, user, human)

// Individual represnts all information about an individual identity
type Individual struct {
	selfID       string
	identityType string
	history      []json.RawMessage
}

// SelfID the self ID of the identity
func (id Individual) SelfID() string {
	return id.selfID
}

// Type the type of identity
func (id Individual) Type() string {
	return IdentityTypeIndividual
}

// History the public key history of an identity
func (id Individual) History() []json.RawMessage {
	return id.history
}

// App represents all information about an app identity
type App struct {
	selfID       string
	identityType string
	history      []json.RawMessage
}

// SelfID the self ID of the identity
func (id App) SelfID() string {
	return id.selfID
}

// Type the type of identity
func (id App) Type() string {
	return IdentityTypeIndividual
}

// History the public key history of an identity
func (id App) History() []json.RawMessage {
	return id.history
}

// Device represents an identities device
type Device string

// GetIdentity gets an identity by its self ID
func (s Service) GetIdentity(selfID string) (Identity, error) {
	var identity Identity

	var resp []byte
	var err error

	switch classifySelfID(selfID) {
	case IdentityTypeIndividual:
		identity = &Individual{}
		resp, err = s.api.Get("/v1/identities/" + selfID)
	case IdentityTypeApp:
		identity = &App{}
		resp, err = s.api.Get("/v1/apps/" + selfID)
	}

	if err != nil {
		return nil, err
	}

	return identity, json.Unmarshal(resp, identity)
}

// GetDevices gets an identities devices
func (s Service) GetDevices(selfID string) ([]Device, error) {
	var devices []Device

	var resp []byte
	var err error

	switch classifySelfID(selfID) {
	case IdentityTypeIndividual:
		resp, err = s.api.Get("/v1/identities/" + selfID + "/devices/")
	case IdentityTypeApp:
		resp, err = s.api.Get("/v1/apps/" + selfID + "/devices/")
	}

	if err != nil {
		return nil, err
	}

	return devices, json.Unmarshal(resp, &devices)
}

// GetHistory gets the public key history of an identity
func (s Service) GetHistory(selfID string) ([]json.RawMessage, error) {
	var keys []json.RawMessage

	var resp []byte
	var err error

	switch classifySelfID(selfID) {
	case IdentityTypeIndividual:
		resp, err = s.api.Get("/v1/identities/" + selfID + "/history/")
	case IdentityTypeApp:
		resp, err = s.api.Get("/v1/apps/" + selfID + "/history/")
	}

	if err != nil {
		return nil, err
	}

	return keys, json.Unmarshal(resp, &keys)
}

func classifySelfID(selfID string) string {
	if len(selfID) > 11 {
		return IdentityTypeApp
	}

	return IdentityTypeIndividual
}
