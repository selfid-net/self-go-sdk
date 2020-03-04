package messages

// IdentityInfoRequest message to request information.
type IdentityInfoRequest struct {
	Typ         string `json:"typ"`
	Cid         string `json:"cid"`
	Iss         string `json:"iss"`
	Sub         string `json:"sub"`
	Aud         string `json:"aud"`
	Iat         string `json:"iat"`
	Exp         string `json:"exp"`
	Jti         string `json:"jti"`
	Description string `json:"description,omitempty"`
	Facts       []Fact `json:"fact"`
}
