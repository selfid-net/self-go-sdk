package identity

import "encoding/json"

var (
	IdentityTypeIndividual = "individual"
	IdentityTypeApp        = "app"
)

// PublicKey the public curve25519 key of a self identity
type PublicKey struct {
	ID  int    `json:"id"`
	Key string `json:"key"`
}

// User identity -> Individual?
// Would be nice to have a way to refer/represent different classes of app or user identity
// so Identity can be either an [Individual, App, Asset], etc.

// Identity represents all information about a self identity
type Identity interface {
	SelfID() string
	Type() string
	PublicKeys() []PublicKey
}

// replace this with whatever we decide for (individual, person, user, human)

// Individual represnts all information about an individual identity
type Individual struct {
	selfID     string
	publicKeys []PublicKey
}

// SelfID the self ID of the identity
func (id Individual) SelfID() string {
	return id.selfID
}

// Type the type of identity
func (id Individual) Type() string {
	return IdentityTypeIndividual
}

// PublicKeys the public keys of the identity
func (id Individual) PublicKeys() []PublicKey {
	return id.publicKeys
}

// App represents all information about an app identity
type App struct {
	selfID     string
	publicKeys []PublicKey
}

// SelfID the self ID of the identity
func (id App) SelfID() string {
	return id.selfID
}

// Type the type of identity
func (id App) Type() string {
	return IdentityTypeIndividual
}

// PublicKeys the public keys of the identity
func (id App) PublicKeys() []PublicKey {
	return id.publicKeys
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

// GetPublicKeys gets the public keys of an identity
func (s Service) GetPublicKeys(selfID string) ([]PublicKey, error) {
	var keys []PublicKey

	var resp []byte
	var err error

	switch classifySelfID(selfID) {
	case IdentityTypeIndividual:
		resp, err = s.api.Get("/v1/identities/" + selfID + "/public_keys/")
	case IdentityTypeApp:
		resp, err = s.api.Get("/v1/apps/" + selfID + "/public_keys/")
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
