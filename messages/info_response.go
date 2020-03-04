package messages

// IdentityInfoResponse message to respond an information request.
type IdentityInfoResponse struct {
	Typ    string `json:"typ"`
	Cid    string `json:"cid"`
	Iss    string `json:"iss"`
	Sub    string `json:"sub"`
	Iat    string `json:"iat"`
	Aud    string `json:"aud"`
	Exp    string `json:"exp"`
	Jti    string `json:"jti"`
	Facts  []Fact `json:"facts"`
	Status string `json:"status"`
}

// Fact returns a given fact by its name if present
func (r *IdentityInfoResponse) Fact(name string) *Fact {
	for i := range r.Facts {
		if r.Facts[i].Fact == name {
			return &r.Facts[i]
		}
	}

	return nil
}
