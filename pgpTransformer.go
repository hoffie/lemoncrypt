package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

// PGPTransformer provides support for converting arbitrary plain messages to PGP/MIME
// messages in a way which allows for bit-perfect reversal of the operation.
type PGPTransformer struct {
	encryptionKey *openpgp.Entity
	signingKey    *openpgp.Entity
	keepHeaders   []string
}

// NewPGPTransformer returns a new PGPTransformer instance.
func NewPGPTransformer(keepHeaders []string) *PGPTransformer {
	return &PGPTransformer{keepHeaders: keepHeaders}
}

// LoadEncryptionKey loads the keyring from the given path and tries to set up the
// first and only public key found there as the encryption target.
func (t *PGPTransformer) LoadEncryptionKey(path, id string) error {
	logger.Debugf("loading encryption key from %s (id=%s)", path, id)
	var err error
	t.encryptionKey, err = t.loadKey(path, id)
	return err
}

// LoadSigningKey loads the keyring from the given path and tries to so set up
// the first and only private key found there as the signing key, optionally
// decrypting it with the given passphrase first.
func (t *PGPTransformer) LoadSigningKey(path, id, passphrase string) error {
	logger.Debugf("loading signing key from %s (id=%s)", path, id)
	var err error
	t.signingKey, err = t.loadKey(path, id)
	if err != nil {
		return err
	}
	priv := t.signingKey.PrivateKey
	if priv == nil {
		return errors.New("signing key lacks private key")
	}
	if priv.Encrypted {
		err := priv.Decrypt([]byte(passphrase))
		if err != nil {
			return fmt.Errorf("failed to decrypt private key: %s", err)
		}
	}
	return nil
}

// loadKey is the internal method which contains the common key loading and
// parsing functionality.
func (t *PGPTransformer) loadKey(path, wantId string) (*openpgp.Entity, error) {
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
		if strings.HasSuffix(id, wantId) {
			foundKey = key
			logger.Infof("loaded key with keyid=%s", id)
			break
		}
	}
	if foundKey == nil {
		return nil, fmt.Errorf("no key with keyid=%s", wantId)
	}
	return foundKey, nil
}

// NewEncryptor returns a new PGPEncryptor instance, which is ready for
// encrypting one single mail.
func (t *PGPTransformer) NewEncryptor() (*PGPEncryptor, error) {
	if t.encryptionKey == nil {
		return nil, errors.New("missing encryption key")
	}
	e := &PGPEncryptor{}
	e.keepHeaders = t.keepHeaders
	e.pgpBuffer = &bytes.Buffer{}
	e.plainBuffer = &bytes.Buffer{}
	var err error
	e.asciiWriter, err = armor.Encode(e.pgpBuffer, "PGP MESSAGE", nil)
	if err != nil {
		return nil, err
	}
	e.pgpWriter, err = openpgp.Encrypt(e.asciiWriter,
		[]*openpgp.Entity{t.encryptionKey}, t.signingKey,
		&openpgp.FileHints{IsBinary: true}, nil)
	if err != nil {
		return nil, err
	}
	return e, nil
}
