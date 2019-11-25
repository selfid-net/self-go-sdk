package selfsdk

// PublicKey models a public key and its identifier
type PublicKey struct {
	ID  int    `json:"id"`
	Key string `json:"key"`
}
