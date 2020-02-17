package messages

// IdentityInfoResponse message to respond an information request.
type IdentityInfoResponse struct {
	Typ    string            `json:"typ"`
	Cid    string            `json:"cid"`
	Iss    string            `json:"iss"`
	Sub    string            `json:"sub"`
	Iat    string            `json:"iat"`
	Aud    string            `json:"aud"`
	Exp    string            `json:"exp"`
	Jti    string            `json:"jti"`
	Fields map[string]Field  `json:"fields"`
	Facts  map[string]string `json:"facts"`
	Status string            `json:"status"`
}
