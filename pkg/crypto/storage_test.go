// Copyright 2020 Self Group Ltd. All Rights Reserved.

package crypto

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

func TestCryptoFileStorageGetAccount(t *testing.T) {
	cfg := StorageConfig{
		StorageDir: createTestDirectory(t),
	}

	defer os.Remove(cfg.StorageDir)

	fs, err := NewFileStorage(cfg)
	require.Nil(t, err)

	err = ioutil.WriteFile(cfg.StorageDir+"/account.pickle", []byte("test"), 0600)
	require.Nil(t, err)

	ad, err := fs.GetAccount()
	require.Nil(t, err)
	assert.Equal(t, []byte("test"), ad)
}

func TestCryptoFileStorageSetAccount(t *testing.T) {
	cfg := StorageConfig{
		StorageDir: createTestDirectory(t),
	}

	defer os.Remove(cfg.StorageDir)

	fs, err := NewFileStorage(cfg)
	require.Nil(t, err)

	err = fs.SetAccount([]byte("test"))
	require.Nil(t, err)

	ad, err := ioutil.ReadFile(cfg.StorageDir + "/account.pickle")
	require.Nil(t, err)
	assert.Equal(t, []byte("test"), ad)
}

func TestCryptoFileStorageGetSession(t *testing.T) {
	cfg := StorageConfig{
		StorageDir: createTestDirectory(t),
	}

	defer os.Remove(cfg.StorageDir)

	fs, err := NewFileStorage(cfg)
	require.Nil(t, err)

	err = ioutil.WriteFile(cfg.StorageDir+"/12345:1-session.pickle", []byte("test"), 0600)
	require.Nil(t, err)

	ad, err := fs.GetSession("12345:1")
	require.Nil(t, err)
	assert.Equal(t, []byte("test"), ad)
}

func TestCryptoFileStorageSetSession(t *testing.T) {
	cfg := StorageConfig{
		StorageDir: createTestDirectory(t),
	}

	defer os.Remove(cfg.StorageDir)

	fs, err := NewFileStorage(cfg)
	require.Nil(t, err)

	err = fs.SetSession("12345:1", []byte("test"))
	require.Nil(t, err)

	ad, err := ioutil.ReadFile(cfg.StorageDir + "/12345:1-session.pickle")
	require.Nil(t, err)
	assert.Equal(t, []byte("test"), ad)
}
