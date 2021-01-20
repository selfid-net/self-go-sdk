// Copyright 2020 Self Group Ltd. All Rights Reserved.

package crypto

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
)

var (
	// ErrNotExist file does not exist
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

// NewFileStorage creates a new storage client that persists to files
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

	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	wb, err := f.Write(account)
	if err != nil {
		return err
	}

	if wb != len(account) {
		return errors.New("incomplete write of encrypted account")
	}

	err = f.Sync()
	if err != nil {
		return err
	}

	return f.Close()
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

// SetSession persists an sessions encoded and encrypted pickle
func (s *FileStorage) SetSession(id string, session []byte) error {
	p := filepath.Join(s.config.StorageDir, id+"-session.pickle")

	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	wb, err := f.Write(session)
	if err != nil {
		return err
	}

	if wb != len(session) {
		return errors.New("incomplete write of encrypted session")
	}

	err = f.Sync()
	if err != nil {
		return err
	}

	return f.Close()
}
