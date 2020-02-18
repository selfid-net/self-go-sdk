package selfsdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	messaging "github.com/selfid-net/self-messaging-client"
	"gopkg.in/square/go-jose.v2"
)

// GenerateToken generates a valid jwt token from the clients public key
func (c *Client) generateToken(expires time.Duration) (string, error) {
	claims, err := json.Marshal(map[string]interface{}{
		"jti": uuid.New().String(),
		"iss": c.AppID,
		"iat": messaging.TimeFunc().Add(-(time.Second)).Unix(), // round down time for inaccurate clocks
		"exp": messaging.TimeFunc().Add(time.Minute).Unix(),
	})

	if err != nil {
		return "", err
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: c.PrivateKey}, nil)
	if err != nil {
		return "", err
	}

	signedPayload, err := signer.Sign(claims)
	if err != nil {
		return "", err
	}

	return signedPayload.CompactSerialize()
}

// Request make a raw request to the self api
func (c *Client) request(method, path string, data []byte, headers map[string]string) (*http.Response, error) {
	u, err := url.Parse(c.baseURL + path)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, u.String(), bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}

	token, err := c.generateToken(time.Minute)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.conn.Do(req)
	if err != nil {
		return resp, err
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted:
		return resp, nil
	default:
		return resp, errored(resp)
	}
}

func (c *Client) get(path string) (*http.Response, error) {
	return c.request("GET", path, nil, nil)
}

func (c *Client) post(path string, ctype string, data []byte) (*http.Response, error) {
	headers := map[string]string{"Content-Type": ctype}
	return c.request("POST", path, data, headers)
}

func (c *Client) put(path string, ctype string, data []byte) (*http.Response, error) {
	headers := map[string]string{"Content-Type": ctype}
	return c.request("PUT", path, data, headers)
}

func (c *Client) delete(path string) (*http.Response, error) {
	return c.request("DELETE", path, nil, nil)
}

func (c *Client) readJSON(resp *http.Response, m interface{}) error {
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, m)
}
