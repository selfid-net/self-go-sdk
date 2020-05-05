package fact

import (
	"encoding/json"
	"errors"
	"github.com/square/go-jose"

	"github.com/tidwall/gjson"
)

var (
	SourcePassport       = "passport"
	SourceDrivingLicense = "driving_license"
	SourceUserSpecified  = "user_specified"

	FactEmail            = "email_address"
	FactPhone            = "phone_number"
	FactDisplayName      = "display_name"
	FactGivenNames       = "given_names"
	FactSurname          = "surname"
	FactSex              = "sex"
	FactIssuingAuthority = "issuing_authority"
	FactNationality      = "nationality"
	FactAddress          = "address"
	FactPlaceOfBirth     = "place_of_birth"
	FactDateOfBirth      = "date_of_birth"
	FactDateOfIssuance   = "date_of_issuance"
	FactDateOfExpiration = "date_of_expiration"

	RequestInformation  = "identity_info_req"
	ResponseInformation = "identity_info_resp"

	StatusAccepted = "accepted"
	StatusRejected = "rejected"
	StatusUnauthorized = "unauthorized"

	ErrFactEmptyName     = errors.New("provided fact does not specify a name")
	ErrFactBadSource     = errors.New("fact must specify one source")
	ErrFactInvalidSource = errors.New("provided fact does not specify a valid source")
)

// Fact specific details about the fact
type Fact struct {
	Fact          string            `json:"fact"`
	Sources       []string          `json:"sources,omitempty"`
	Origin        string            `json:"iss,omitempty"`
	Operator      string            `json:"operator,omitempty"`
	Attestations  []json.RawMessage `json:"attestations,omitempty"`
	ExpectedValue string            `json:"expected_value,omitempty"`
	AttestedValue string            `json:"-"`
	payloads      [][]byte
	results       []string
	value         string
}

// AttestedValues returns all attested values for an attestations
func (f *Fact) AttestedValues() []string {
	values := make([]string, len(f.payloads))

	for i, p := range f.payloads {
		v := gjson.GetBytes(p, f.Fact).String()
		values[i] = v
	}

	return values
}

// Result the result returned from an intermediary request
// This will return true if all of the expectations were met
func (f *Fact) Result() bool {
	if len(f.Attestations) < 1 {
		return false
	}

	for _, a := range f.Attestations {
		jws, err := jose.ParseSigned(string(a))
		if err != nil {
			return false
		}

		if !gjson.GetBytes(jws.UnsafePayloadWithoutVerification(), f.Fact).Bool() {
			return false
		}
	}

	return true
}

func (f *Fact) validate() error {
	if f.Fact == "" {
		return ErrFactEmptyName
	}

	for _, s := range f.Sources {
		if s != SourcePassport || s != SourceDrivingLicense || s != SourceUserSpecified {
			return ErrFactInvalidSource
		}
	}

	return nil
}
