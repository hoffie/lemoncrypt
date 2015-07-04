package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

type PGPDecryptor struct {
	buf                  *bytes.Buffer
	headers              textproto.MIMEHeader
	keyring              openpgp.EntityList
	decryptionPassphrase string
}

func (d *PGPDecryptor) Init(signingKey, decryptionKey *openpgp.Entity, decryptionPassphrase string) error {
	d.buf = &bytes.Buffer{}
	d.decryptionPassphrase = decryptionPassphrase
	d.keyring = openpgp.EntityList{signingKey, decryptionKey}
	return nil
}

func (d *PGPDecryptor) Write(data []byte) (int, error) {
	return d.buf.Write(data)
}

// GetBytes returns the decrypted message as a byte array.
func (d *PGPDecryptor) GetBytes() ([]byte, error) {
	var err error
	plainReader := bufio.NewReader(d.buf)
	mimeReader := textproto.NewReader(plainReader)
	d.headers, err = mimeReader.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	if !d.isLemoncrypt() {
		logger.Debugf("returning non-lemoncrypt message without modification")
		return d.buf.Bytes(), nil
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
	md, err := openpgp.ReadMessage(block.Body, d.keyring, d.decryptDecryptionKey, nil /*config*/)
	if err != nil {
		return nil, fmt.Errorf("openpgp.ReadMessage failed: %s", err)
	}
	outBytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("reading openpgp stream failed: %s", err)
	}
	if md.SignatureError != nil {
		return nil, fmt.Errorf("signature verification failed: %s", md.SignatureError)
	}
	return outBytes, nil
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
