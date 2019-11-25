package messages

// Field structure.
type Field struct {
	Field    string `json:"field"`
	Source   string `json:"source,omitempty"`
	Origin   string `json:"iss,omitempty"`
	Operator string `json:"operator,omitempty"`
	Value    string `json:"value,omitempty"`
	Result   string `json:"result,omitempty"`
}
