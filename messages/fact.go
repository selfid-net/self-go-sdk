package messages

import (
	"errors"
)

// Fact structure.
type Fact struct {
	Fact         string        `json:"fact"`
	Sources      []string      `json:"source,omitempty"`
	Origin       string        `json:"iss,omitempty"`
	Operator     string        `json:"operator,omitempty"`
	Value        string        `json:"value,omitempty"`
	Attestations []Attestation `json:"attestations"`
}

// Result returns the aggregated value for a given fact
func (f *Fact) Result() (string, error) {
	var value string

	for _, a := range f.Attestations {
		f := a.value(f.Fact)
		if f == "" {
			return "", errors.New("attestation does not contain the claimed fact")
		}

		if value == "" {
			value = f
			continue
		}

		if value != f {
			return "", errors.New("fact contains attestations with values that do not match")
		}
	}

	return value, nil
}
