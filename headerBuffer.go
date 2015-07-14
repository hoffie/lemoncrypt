package main

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
)

// HeaderBuffer is a special type of Buffer. Writes to it are recorded
// as long as they are part of an email header block. Any further writes will
// silently be discarded with no errors.  When reading back from the buffer,
// the whole header block is returned with \r's stripped and all non-MIME
// header lines removed. Non-MIME header lines are all lines which contain
// no dot and are not continuation lines.
//
// This type is used in order to record MIME headers in a way which can be parsed,
// even if "Received" lines or non-standard Outlook MIME headers are contained
// (the latter appear in the Enron test cases).
type HeaderBuffer struct {
	buf             *bytes.Buffer
	headersComplete bool
	headerBytes     []byte
}

// NewHeaderBuffer returns a new HeaderBuffer instance.
func NewHeaderBuffer() *HeaderBuffer {
	return &HeaderBuffer{buf: &bytes.Buffer{}}
}

// Read implements the io.Reader interface and returns the whole header block with
// above transformations applied.
// The final double new line is included. An error is returned if no complete
// header block has been found.
func (hb *HeaderBuffer) Read(buf []byte) (int, error) {
	if !hb.headersComplete {
		return 0, errors.New("unterminated or empty header block")
	}
	return hb.buf.Read(buf)
}

// Write implements the io.Writer interface and analyzes the incoming data in order
// to detect the end of the header block.
// All header block data is written to an internal buffer.
func (hb *HeaderBuffer) Write(data []byte) (int, error) {
	if hb.headersComplete {
		// quick return if we are not awaiting any more header data
		return len(data), nil
	}
	hb.headerBytes = append(hb.headerBytes, data...)
	hb.checkForCompleteHeader()
	if hb.headersComplete {
		hb.storeHeaderBlock()
	}
	return len(data), nil
}

// checkForCompleteHeader analyzes the buffer content in order to find out if
// the header block has been completed. If it has, headersComplete is set to true
// and headerBytes is adjusted so that it contains just the header.
func (hb *HeaderBuffer) checkForCompleteHeader() {
	var prev byte
	for idx, char := range hb.headerBytes {
		if prev == '\n' && char == '\n' {
			hb.headerBytes = hb.headerBytes[:idx+1]
			hb.headersComplete = true
			return
		}
		if char != '\r' {
			prev = char
		}
	}
}

// storeHeaderBlock grabs the header block bytes from the buffer, removes all
// non-MIME lines and stores it for later retrieval.
func (hb *HeaderBuffer) storeHeaderBlock() {
	s := bufio.NewScanner(bytes.NewBuffer(hb.headerBytes))
	for s.Scan() {
		line := s.Text()
		if len(line) > 0 && !strings.Contains(line, ":") && line[0] != ' ' && line[0] != '\t' {
			continue
		}
		hb.buf.WriteString(line)
		hb.buf.Write([]byte("\n"))
	}
}
