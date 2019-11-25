package selfsdk

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
)

var (
	// ErrInvalidKeyEncoding is returned when a given private or public key is not correctly encoded with base64
	ErrInvalidKeyEncoding = errors.New("specified key is not encoded with base64")
	// ErrInvalidAuthSubject is returned when an authentication response does not contain the self id of the authenticating party
	ErrInvalidAuthSubject = errors.New("auth response is missing subjects self id")
	// ErrInvalidAuthIssuer is returned when an authentication response specifies an issuer that does not match the identity of the issuing application
	ErrInvalidAuthIssuer = errors.New("auth response issuer does not match the configured app id")
	// ErrAuthenticationRequestExpired is returned when an authentication response is received after the indicated expiry period
	ErrAuthenticationRequestExpired = errors.New("authentication response has expired")
	// ErrAuthRejected is returned when the authenticating party rejects the request to authenticate
	ErrAuthRejected = errors.New("authentication rejected by user")
	// ErrInvalidAuthStatus is returned when the authentication response contains an invalid status
	ErrInvalidAuthStatus = errors.New("authentication response contains an invalid status")
)

type errorMessage struct {
	Error string `json:"error"`
}

func errored(resp *http.Response) error {
	var e errorMessage

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.New(resp.Status)
	}

	err = json.Unmarshal(data, &e)
	if err != nil {
		return errors.New(resp.Status)
	}

	if e.Error != "" {
		return errors.New(e.Error)
	}

	return errors.New(resp.Status)
}
