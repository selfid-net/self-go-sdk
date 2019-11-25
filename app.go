package selfsdk

// App represents an app record.
type App struct {
	ID         string      `json:"id"`
	PublicKeys []PublicKey `json:"public_keys"`
}

// Keys returns all public keys as a string slice
func (m App) Keys() []string {
	keys := make([]string, len(m.PublicKeys))

	for i := range m.PublicKeys {
		keys[i] = m.PublicKeys[i].Key
	}

	return keys
}
