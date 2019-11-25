package selfsdk

// Identity represents an identity record.
type Identity struct {
	ID         string      `json:"id"`
	PublicKeys []PublicKey `json:"public_keys"`
}

// Keys returns all public keys as a string slice
func (m Identity) Keys() []string {
	keys := make([]string, len(m.PublicKeys))

	for i := range m.PublicKeys {
		keys[i] = m.PublicKeys[i].Key
	}

	return keys
}
