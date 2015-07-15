package main

import (
	"errors"
	"io"
	"reflect"
)

// Verifier acts as a Writer and ensures that all data which is written to it
// matches the data from the configured reader.
// Essentially, it compares the contents of the reader and the writer step by step
// in a more performant way than by working with intermediate buffers.
type Verifier struct {
	target         io.Reader
	expectedLength int64
	byteCounter    int64
}

// NewVerifier returns a new Verifier instance.
// r is the reader where all written data is matched against.
// length is the expected length.
func NewVerifier(r io.Reader, length int64) *Verifier {
	v := &Verifier{
		target:         r,
		expectedLength: length,
	}
	return v
}

// Write implements the Writer interface.
// Any data written to this Verifier is immediately matched against data
// from the target which is read as needed.
// In case of a mismatch, Write returns an error.
// Multiple write calls are allowed.
func (v *Verifier) Write(wBuf []byte) (int, error) {
	totalLen := len(wBuf)
	rBuf := make([]byte, totalLen)
	toRead := totalLen
	for toRead > 0 {
		l, err := v.target.Read(rBuf)
		if err != nil {
			return l, err
		}
		if !reflect.DeepEqual(wBuf[0:l], rBuf[0:l]) {
			return l, errors.New("bytes mismatch")
		}
		v.byteCounter += int64(l)
		toRead -= l
		wBuf = wBuf[l:]
	}
	return totalLen, nil
}

// Equal returns whether the written/read data matched and has equal length.
// This function may not be called when there is still data to be processed.
func (v *Verifier) Equal() bool {
	buf := make([]byte, 1)
	l, err := v.target.Read(buf)
	if l != 0 {
		logger.Debugf("verifier: read one byte, but expected EOF")
		return false
	}
	if err != io.EOF {
		logger.Debugf("expected EOF, but got %s", err)
		return false
	}
	return v.byteCounter == v.expectedLength
}
