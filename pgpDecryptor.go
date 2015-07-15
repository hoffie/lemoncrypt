package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

// PGPDecryptor handles decryption of a single mail message.
type PGPDecryptor struct {
	buf                  *bytes.Buffer
	headers              textproto.MIMEHeader
	keyring              openpgp.EntityList
	md                   *openpgp.MessageDetails
	decryptionPassphrase string
}

// NewPGPDecryptor returns a new PGPDecryptor instance, initialized with the given parameters.
func NewPGPDecryptor(signingKey, decryptionKey *openpgp.Entity, decryptionPassphrase string) *PGPDecryptor {
	d := &PGPDecryptor{}
	d.buf = &bytes.Buffer{}
	d.decryptionPassphrase = decryptionPassphrase
	d.keyring = openpgp.EntityList{signingKey, decryptionKey}
	return d
}

func (d *PGPDecryptor) Write(data []byte) (int, error) {
	return d.buf.Write(data)
}

// GetReader returns the decrypted message as a Reader.
// IMPORTANT: The reader will return unverified data. .Verify() has to
// be called before working with the data!
func (d *PGPDecryptor) GetReader() (io.Reader, error) {
	var err error
	plainReader := bufio.NewReader(d.buf)
	mimeReader := textproto.NewReader(plainReader)
	d.headers, err = mimeReader.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	if !d.isLemoncrypt() {
		logger.Debugf("returning non-lemoncrypt message without modification")
		return d.buf, nil
	}
	boundary, err := d.getBoundary()
	multipartReader := multipart.NewReader(mimeReader.R, boundary)
	part, err := multipartReader.NextPart()
	if err != nil {
		return nil, err
	}
	ctype, _, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}
	if ctype != "application/pgp-encrypted" {
		return nil, fmt.Errorf("unexpected Content-Type=%s, expected application/pgp-encrypted", ctype)
	}
	part, err = multipartReader.NextPart()
	if err != nil {
		return nil, err
	}
	ctype, _, err = mime.ParseMediaType(part.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}
	if ctype != "application/octet-stream" {
		return nil, fmt.Errorf("unexpected Content-Type=%s, expected application/octet-stream", ctype)
	}
	block, err := armor.Decode(part)
	if err != nil {
		return nil, fmt.Errorf("failed to de-armor: %s", err)
	}
	d.md, err = openpgp.ReadMessage(block.Body, d.keyring, d.decryptDecryptionKey, nil /*config*/)
	if err != nil {
		return nil, fmt.Errorf("openpgp.ReadMessage failed: %s", err)
	}
	return d.md.UnverifiedBody, nil
}

func (d *PGPDecryptor) Verify() error {
	if d.md.SignatureError != nil {
		return fmt.Errorf("signature verification failed: %s", d.md.SignatureError)
	}
	return nil
}

func (d *PGPDecryptor) decryptDecryptionKey(keys []openpgp.Key, symmetric bool) ([]byte, error) {
	// why do we need the prompt function here although our keyring contains a decrypted
	// private key?
	// .ReadMessage chose to call .DecryptionKeys() on the keyring, which actually duplicates
	// the key material but not the decryption state, so .ReadMessage only sees encrypted keys.
	err := errors.New("requiring passphrase")
	for _, key := range keys {
		err := key.PrivateKey.Decrypt([]byte(d.decryptionPassphrase))
		if err == nil {
			return nil, nil
		}
	}
	return nil, err
}

// isLemoncrypt returns true if the message currently in the buffer
// looks like one which had been encrypted by lemoncrypt.
// This check is based on our custom header.
func (d *PGPDecryptor) isLemoncrypt() bool {
	if d.headers.Get(CustomHeader) == "" {
		return false
	}
	ctype := d.headers.Get("Content-Type")
	if !strings.HasPrefix(ctype, "multipart/encrypted") {
		logger.Warningf("message has lemoncrypt header but is not encrypted?")
		return false
	}
	return true
}

// getBoundary extracts the boundary parameter from the Content-Type header and returns it.
func (d *PGPDecryptor) getBoundary() (string, error) {
	_, params, err := mime.ParseMediaType(d.headers.Get("Content-Type"))
	if err != nil {
		return "", err
	}
	boundary, exists := params["boundary"]
	if !exists {
		return "", errors.New("missing MIME boundary")
	}
	return boundary, nil
}
