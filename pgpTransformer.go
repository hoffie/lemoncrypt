package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/openpgp"
)

const (
	// msgIDPrefix is the string which is prepended to each Message-Id when
	// converting messages.
	msgIDPrefix = "lemoncrypt."

	// CustomHeader is the key of the MIME header which is added to each
	// message.
	CustomHeader = "X-Lemoncrypt"
)

// PGPTransformer provides support for converting arbitrary plain messages to PGP/MIME
// messages in a way which allows for bit-perfect reversal of the operation.
type PGPTransformer struct {
	signingKey              *openpgp.Entity
	encryptionKey           *openpgp.Entity
	encryptionKeyPassphrase string
	keepHeaders             []string
}

// NewPGPTransformer returns a new PGPTransformer instance.
func NewPGPTransformer(keepHeaders []string) *PGPTransformer {
	return &PGPTransformer{keepHeaders: keepHeaders}
}

// LoadEncryptionKey loads the keyring from the given path and tries to set up the
// first and only public key found there as the encryption target.
func (t *PGPTransformer) LoadEncryptionKey(path, id, passphrase string) error {
	logger.Debugf("loading encryption key from %s (id=%s)", path, id)
	var err error
	t.encryptionKey, err = t.loadKey(path, id, passphrase)
	if err != nil {
		return err
	}
	t.encryptionKeyPassphrase = passphrase
	return nil
}

// LoadSigningKey loads the keyring from the given path and tries to so set up
// the first and only private key found there as the signing key, optionally
// decrypting it with the given passphrase first.
func (t *PGPTransformer) LoadSigningKey(path, id, passphrase string) error {
	logger.Debugf("loading signing key from %s (id=%s)", path, id)
	var err error
	t.signingKey, err = t.loadKey(path, id, passphrase)
	return err
}

// loadKey is the internal method which contains the common key loading and
// parsing functionality.
func (t *PGPTransformer) loadKey(path, wantID, passphrase string) (*openpgp.Entity, error) {
	keyringReader, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer keyringReader.Close()
	keyring, err := openpgp.ReadKeyRing(keyringReader)
	if err != nil {
		return nil, err
	}
	var foundKey *openpgp.Entity
	for _, key := range keyring {
		id := key.PrimaryKey.KeyIdString()
		if strings.HasSuffix(id, wantID) {
			foundKey = key
			logger.Infof("loaded key with keyid=%s", id)
			break
		}
	}
	if foundKey == nil {
		return nil, fmt.Errorf("no key with keyid=%s", wantID)
	}
	priv := foundKey.PrivateKey
	if priv == nil {
		return nil, errors.New("signing key lacks private key")
	}
	if priv.Encrypted {
		err := priv.Decrypt([]byte(passphrase))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt private key: %s", err)
		}
	}
	return foundKey, nil
}

// NewEncryptor returns a new PGPEncryptor instance, which is ready for
// encrypting one single mail.
func (t *PGPTransformer) NewEncryptor() (*PGPEncryptor, error) {
	return NewPGPEncryptor(t.encryptionKey, t.signingKey, t.keepHeaders)
}

// NewDecryptor returns and initializes a new PGPDecryptor instance.
func (t *PGPTransformer) NewDecryptor() *PGPDecryptor {
	return NewPGPDecryptor(t.signingKey, t.encryptionKey, t.encryptionKeyPassphrase)
}
