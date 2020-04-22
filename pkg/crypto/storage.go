package crypto

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
)

var (
	ErrNotExist = os.ErrNotExist
)
var perr *os.PathError

// StorageConfig represents all storage
type StorageConfig struct {
	StorageDir string
}

// FileStorage the default storage for sessions and account data
type FileStorage struct {
	config StorageConfig
}

// NewStorage creates a new storage client that persists to files
func NewFileStorage(config StorageConfig) (*FileStorage, error) {
	return &FileStorage{config}, os.MkdirAll(config.StorageDir, 0700)
}

// GetAccount gets an accounts encoded and encrypted pickle
// This function will return nil data and error if an account doesn'texist
func (s *FileStorage) GetAccount() ([]byte, error) {
	p := filepath.Join(s.config.StorageDir, "account.pickle")

	data, err := ioutil.ReadFile(p)
	if err != nil {
		if err == os.ErrNotExist || errors.As(err, &perr) {
			return nil, nil
		}
		return nil, err
	}

	return data, nil
}

// SetAccount persists an accounts encoded and encrypted pickle
func (s *FileStorage) SetAccount(account []byte) error {
	p := filepath.Join(s.config.StorageDir, "account.pickle")
	return ioutil.WriteFile(p, account, 0600)
}

// GetSession gets an sessions encoded and encrypted pickle
func (s *FileStorage) GetSession(id string) ([]byte, error) {
	p := filepath.Join(s.config.StorageDir, id+"-session.pickle")

	data, err := ioutil.ReadFile(p)
	if err != nil {
		if err == os.ErrNotExist || errors.As(err, &perr) {
			return nil, nil
		}
		return nil, err
	}

	return data, nil
}

// SetAccount persists an sessions encoded and encrypted pickle
func (s *FileStorage) SetSession(id string, session []byte) error {
	p := filepath.Join(s.config.StorageDir, id+"-session.pickle")
	return ioutil.WriteFile(p, session, 0600)
}
