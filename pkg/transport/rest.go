package transport

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"golang.org/x/crypto/ed25519"
)

// RestConfig configuration for connecting to selfs api
type RestConfig struct {
	SelfID     string
	KeyID      string
	PrivateKey ed25519.PrivateKey
	APIURL     string
	Client     *http.Client
}

// Rest client for interacting with self's rest api
type Rest struct {
	config RestConfig
}

// NewRest creates a new rest transport
func NewRest(config RestConfig) (*Rest, error) {
	return &Rest{config}, nil
}

// Get perform an http get request
func (c *Rest) Get(path string) ([]byte, error) {
	return c.request("GET", path, nil, nil)
}

// Post perform an http post request
func (c *Rest) Post(path string, ctype string, data []byte) ([]byte, error) {
	headers := map[string]string{"Content-Type": ctype}
	return c.request("POST", path, data, headers)
}

// Put perform an http put request
func (c *Rest) Put(path string, ctype string, data []byte) ([]byte, error) {
	headers := map[string]string{"Content-Type": ctype}
	return c.request("PUT", path, data, headers)
}

// Delete perform an http delete request
func (c *Rest) Delete(path string) ([]byte, error) {
	return c.request("DELETE", path, nil, nil)
}

// Request make a raw request to the self api
func (c *Rest) request(method, path string, data []byte, headers map[string]string) ([]byte, error) {
	u, err := url.Parse(c.config.APIURL + path)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, u.String(), bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}

	token, err := GenerateToken(c.config.SelfID, c.config.KeyID, c.config.PrivateKey)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.config.Client.Do(req)
	if err != nil {
		return nil, err
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted:
		return ioutil.ReadAll(resp.Body)
	default:
		return nil, errored(resp)
	}
}

type apiResponse struct {
	Error string `json:"error"`
}

func errored(resp *http.Response) error {
	var e apiResponse

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
