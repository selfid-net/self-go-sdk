package identity

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type restMock struct {
	body string
	err  error
}

func (r restMock) Get(path string) ([]byte, error) {
	return []byte(r.body), nil
}

func TestGetScore(t *testing.T) {
	var flagtests = []struct {
		body  string
		score int64
		err   error
	}{
		{`{"score":22}`, int64(22), nil},
		{`{"error_code":404,"message":"not enough credits"}`, int64(0), errors.New("not enough credits")},
	}

	for _, tt := range flagtests {
		i := Service{
			api: restMock{
				body: tt.body,
				err:  nil,
			},
		}
		score, err := i.GetScore("4333222111")
		require.Equal(t, tt.err, err)
		assert.Equal(t, tt.score, score)
	}
}
