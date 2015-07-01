package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

type PGPTransformer struct {
	pgpBuffer     *bytes.Buffer
	outBuffer     *bytes.Buffer
	pgpWriter     io.WriteCloser
	asciiWriter   io.WriteCloser
	encryptionKey *openpgp.Entity
	signingKey    *openpgp.Entity
}

func NewPGPTransformer() *PGPTransformer {
	return &PGPTransformer{}
}

func (w *PGPTransformer) LoadEncryptionKey(path string) error {
	logger.Debugf("loading encryption key from %s", path)
	var err error
	w.encryptionKey, err = w.loadKey(path)
	return err
}

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

func (w *PGPTransformer) Reset() error {
	w.pgpBuffer = &bytes.Buffer{}
	var err error
	w.asciiWriter, err = armor.Encode(w.pgpBuffer, "PGP MESSAGE", nil)
	if err != nil {
		return err
	}
	if w.encryptionKey == nil {
		return errors.New("missing encryption key")
	}
	w.pgpWriter, err = openpgp.Encrypt(w.asciiWriter,
		[]*openpgp.Entity{w.encryptionKey}, w.signingKey,
		&openpgp.FileHints{IsBinary: true}, nil)
	return err
}

func (w *PGPTransformer) Write(data []byte) (int, error) {
	return w.pgpWriter.Write(data)
}

func (w *PGPTransformer) GetBytes() ([]byte, error) {
	w.finalizePGP()
	err := w.finalizeMIME()
	if err != nil {
		return nil, err
	}
	return w.outBuffer.Bytes(), nil
}

func (w *PGPTransformer) finalizePGP() {
	w.pgpWriter.Close()
	w.asciiWriter.Close()
}

func (w *PGPTransformer) finalizeMIME() error {
	tmp := make([]byte, 30)
	_, err := io.ReadFull(rand.Reader, tmp)
	if err != nil {
		return err
	}
	boundary := fmt.Sprintf("%x", tmp)
	w.outBuffer = &bytes.Buffer{}
	w.outBuffer.WriteString(
		"MIME-Version: 1.0\n" +
			"Content-Type: multipart/encrypted;\n" +
			" protocol=\"application/pgp-encrypted\";\n" +
			" boundary=\"" + boundary + "\"\n\n" +
			"OpenPGP/MIME\n" +
			"--" + boundary + "\n" +
			"Content-Type: application/pgp-encrypted\n\n" +
			"Version: 1\n\n" +
			"--" + boundary + "\n" +
			"Content-Type: application/octet-stream; name=\"encrypted.asc\"\n" +
			"Content-Disposition: inline; filename=\"encrypted.asc\"\n\n" +
			string(w.pgpBuffer.Bytes()) + "\n--" + boundary + "--")
	return nil
}
