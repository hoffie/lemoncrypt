package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"os"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

// PGPTransformer provides support for converting arbitrary plain messages to PGP/MIME
// messages in a way which allows for bit-perfect reversal of the operation.
type PGPTransformer struct {
	pgpBuffer     *bytes.Buffer
	outBuffer     *bytes.Buffer
	plainBuffer   *bytes.Buffer
	pgpWriter     io.WriteCloser
	asciiWriter   io.WriteCloser
	encryptionKey *openpgp.Entity
	signingKey    *openpgp.Entity
	keepHeaders   []string
	headers       textproto.MIMEHeader
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

// Reset configures the PGPTransformer to be ready for the first or next message
// transformation.
// Call this method before initially passing the transformer data or before passing
// it any new data after finishing handling of the previous item.
func (w *PGPTransformer) Reset() error {
	w.pgpBuffer = &bytes.Buffer{}
	w.plainBuffer = &bytes.Buffer{}
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

// Write passes the given data to the underlying PGP encryptor.
func (w *PGPTransformer) Write(data []byte) (int, error) {
	_, err := w.plainBuffer.Write(data)
	if err != nil {
		return 0, err
	}
	return w.pgpWriter.Write(data)
}

// GetBytes returns the encrypted message as a byte array.
func (w *PGPTransformer) GetBytes() ([]byte, error) {
	err := w.finalizePGP()
	if err != nil {
		return nil, err
	}
	err = w.finalizeMIME()
	if err != nil {
		return nil, err
	}
	return w.outBuffer.Bytes(), nil
}

// finalizePGP ends the PGP encryption process and ascii-encoding process.
func (w *PGPTransformer) finalizePGP() error {
	err := w.pgpWriter.Close()
	if err != nil {
		return err
	}
	return w.asciiWriter.Close()
}

// finalizeMIME finally encodes the PGP ascii-armored data in a MIME message.
func (w *PGPTransformer) finalizeMIME() error {
	w.outBuffer = &bytes.Buffer{}
	err := w.writePlainHeaders()
	if err != nil {
		return err
	}
	return w.writeMIMEStructure()
}

// writePlainHeaders generates Message-Id and copies all the plain headers which are
// configured to be copied up from the original message to the output buffer.
func (w *PGPTransformer) writePlainHeaders() error {
	plainReader := bufio.NewReader(w.plainBuffer)
	mimeReader := textproto.NewReader(plainReader)
	var err error
	w.headers, err = mimeReader.ReadMIMEHeader()
	if err != nil {
		return err
	}
	ctype := w.headers.Get("Content-Type")
	if strings.HasPrefix(ctype, "multipart/encrypted") {
		return errors.New("already encrypted")
	}
	w.writeMessageID()
	w.writeKeptHeaders()
	return nil
}

// writeMessageID outputs the current message's adapted message id.
func (w *PGPTransformer) writeMessageID() {
	msgid := w.headers.Get("Message-Id")
	if msgid != "" {
		prefix := "lemoncrypt."
		if len(msgid) > 1 && msgid[0] == '<' {
			msgid = msgid[0:1] + prefix + msgid[1:]
		} else {
			msgid += prefix + msgid[1:]
		}
	}
	w.outBuffer.WriteString("Message-Id: " + msgid + "\n")
}

// writeKeptHeaders outputs the current message's copied plaintext headers.
func (w *PGPTransformer) writeKeptHeaders() {
	for _, key := range w.keepHeaders {
		val := w.headers.Get(key)
		if val == "" {
			// don't attempt to copy empty headers
			continue
		}
		//FIXME proper line wrapping; not obvious how go does it
		w.outBuffer.WriteString(key + ": " + val + "\n")
	}
}

// writeMIMEStructure writes the basic MIME structure and the encrypted content
// to the output buffer.
func (w *PGPTransformer) writeMIMEStructure() error {
	boundary, err := generateBoundary()
	if err != nil {
		return err
	}
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

// generateBoundary creates a random boundary string suitable for
// MIME part separation.
func generateBoundary() (string, error) {
	tmp := make([]byte, 30)
	_, err := io.ReadFull(rand.Reader, tmp)
	if err != nil {
		return "", err
	}
	boundary := fmt.Sprintf("%x", tmp)
	return boundary, nil
}
