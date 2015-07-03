package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"

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
func (w *PGPTransformer) LoadEncryptionKey(path string) error {
	logger.Debugf("loading encryption key from %s", path)
	var err error
	w.encryptionKey, err = w.loadKey(path)
	return err
}

// LoadSigningKey loads the keyring from the given path and tries to so set up
// the first and only private key found there as the signing key, optionally
// decrypting it with the given passphrase first.
func (w *PGPTransformer) LoadSigningKey(path, passphrase string) error {
	logger.Debugf("loading signing key from %s", path)
	var err error
	w.signingKey, err = w.loadKey(path)
	if err != nil {
		return err
	}
	priv := w.signingKey.PrivateKey
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
func (w *PGPTransformer) loadKey(path string) (*openpgp.Entity, error) {
	keyringReader, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer keyringReader.Close()
	keyring, err := openpgp.ReadArmoredKeyRing(keyringReader)
	if err != nil {
		return nil, err
	}
	if len(keyring) != 1 {
		logger.Errorf("encryption key ring contains %d keys; expected 1", len(keyring))
		return nil, errors.New("encryption key ring must contain exactly one key")
	}
	return keyring[0], nil
}

// NewEncryptor returns a new PGPEncryptor instance, which is ready for
// encrypting one single mail.
func (w *PGPTransformer) NewEncryptor() (*PGPEncryptor, error) {
	if w.encryptionKey == nil {
		return nil, errors.New("missing encryption key")
	}
	e := &PGPEncryptor{}
	e.keepHeaders = w.keepHeaders
	e.pgpBuffer = &bytes.Buffer{}
	e.plainBuffer = &bytes.Buffer{}
	var err error
	e.asciiWriter, err = armor.Encode(e.pgpBuffer, "PGP MESSAGE", nil)
	if err != nil {
		return nil, err
	}
	e.pgpWriter, err = openpgp.Encrypt(e.asciiWriter,
		[]*openpgp.Entity{w.encryptionKey}, w.signingKey,
		&openpgp.FileHints{IsBinary: true}, nil)
	if err != nil {
		return nil, err
	}
	return e, nil
}
