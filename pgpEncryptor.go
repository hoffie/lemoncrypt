package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

// PGPEncryptor implements PGP encryption; use PGPTransformer.NewEncryptor
// to get a properly configured instance.
type PGPEncryptor struct {
	pgpBuffer    *bytes.Buffer
	outBuffer    *bytes.Buffer
	headerBuffer *HeaderBuffer
	pgpWriter    io.WriteCloser
	asciiWriter  io.WriteCloser
	keepHeaders  []string
	headers      textproto.MIMEHeader
}

// NewPGPEncryptor returns a new PGPEncryptor instance, prepared for encrypting one single
// mail with the given parameters.
func NewPGPEncryptor(signingKey, encryptionKey *openpgp.Entity, keepHeaders []string) (*PGPEncryptor, error) {
	if encryptionKey == nil {
		return nil, errors.New("missing encryption key")
	}
	e := &PGPEncryptor{}
	e.keepHeaders = keepHeaders
	e.pgpBuffer = &bytes.Buffer{}
	e.headerBuffer = NewHeaderBuffer()
	var err error
	e.asciiWriter, err = armor.Encode(e.pgpBuffer, "PGP MESSAGE", nil)
	if err != nil {
		return nil, err
	}
	cfg := &packet.Config{
		DefaultCipher: packet.CipherAES256,
		DefaultHash:   crypto.SHA256,
	}
	e.pgpWriter, err = openpgp.Encrypt(e.asciiWriter,
		[]*openpgp.Entity{encryptionKey}, signingKey,
		&openpgp.FileHints{IsBinary: true}, cfg)
	if err != nil {
		return nil, err
	}
	return e, nil
}

// Write passes the given data to the underlying PGP encryptor.
func (e *PGPEncryptor) Write(data []byte) (int, error) {
	_, err := e.headerBuffer.Write(data)
	if err != nil {
		return 0, err
	}
	return e.pgpWriter.Write(data)
}

// GetBytes returns the encrypted message as a byte array.
func (e *PGPEncryptor) GetBytes() ([]byte, error) {
	err := e.finalizePGP()
	if err != nil {
		return nil, err
	}
	err = e.finalizeMIME()
	if err != nil {
		return nil, err
	}
	return e.outBuffer.Bytes(), nil
}

// finalizePGP ends the PGP encryption process and ascii-encoding process.
func (e *PGPEncryptor) finalizePGP() error {
	err := e.pgpWriter.Close()
	if err != nil {
		return err
	}
	return e.asciiWriter.Close()
}

// finalizeMIME finally encodes the PGP ascii-armored data in a MIME message.
func (e *PGPEncryptor) finalizeMIME() error {
	e.outBuffer = &bytes.Buffer{}
	err := e.writePlainHeaders()
	if err != nil {
		return err
	}
	return e.writeMIMEStructure()
}

// writePlainHeaders generates Message-Id and copies all the plain headers which are
// configured to be copied up from the original message to the output buffer.
func (e *PGPEncryptor) writePlainHeaders() error {
	plainReader := bufio.NewReader(e.headerBuffer)
	mimeReader := textproto.NewReader(plainReader)
	var err error
	e.headers, err = mimeReader.ReadMIMEHeader()
	if err != nil {
		return err
	}
	ctype := e.headers.Get("Content-Type")
	if strings.HasPrefix(ctype, "multipart/encrypted") {
		return errors.New("already encrypted")
	}
	e.writeMessageID()
	e.writeKeptHeaders()
	e.writeLemoncryptHeader()
	return nil
}

// writeMessageID outputs the current message's adapted message id.
func (e *PGPEncryptor) writeMessageID() {
	msgid := e.headers.Get("Message-Id")
	if msgid != "" {
		if len(msgid) > 1 && msgid[0] == '<' {
			msgid = msgid[0:1] + msgIDPrefix + msgid[1:]
		} else {
			msgid += msgIDPrefix + msgid[1:]
		}
	}
	e.outBuffer.WriteString("Message-Id: " + msgid + "\n")
}

func (e *PGPEncryptor) writeLemoncryptHeader() {
	e.outBuffer.WriteString(CustomHeader + ": v0.1\n")
}

// writeKeptHeaders outputs the current message's copied plaintext headers.
func (e *PGPEncryptor) writeKeptHeaders() {
	for _, key := range e.keepHeaders {
		val := e.headers.Get(key)
		if val == "" {
			// don't attempt to copy empty headers
			continue
		}
		//FIXME proper line wrapping; not obvious how go does it
		e.outBuffer.WriteString(key + ": " + val + "\n")
	}
}

// writeMIMEStructure writes the basic MIME structure and the encrypted content
// to the output buffer.
func (e *PGPEncryptor) writeMIMEStructure() error {
	boundary, err := generateBoundary()
	if err != nil {
		return err
	}
	e.outBuffer.WriteString(
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
			string(e.pgpBuffer.Bytes()) + "\n--" + boundary + "--")
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
