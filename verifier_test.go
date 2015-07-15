package main

import (
	"bytes"

	. "gopkg.in/check.v1"
)

type VerifierSuite struct{}

var _ = Suite(&VerifierSuite{})

var verifierTests = []struct {
	reader string
	writer string
	result bool
}{
	{"foo", "foo", true},
	{"foo", "fo1", false},
	{"foo", "fooa", false},
	{"fooa", "foo", false},
}

func (s *VerifierSuite) Test(c *C) {
	for _, tt := range verifierTests {
		r := bytes.NewBufferString(tt.reader)
		v := NewVerifier(r, int64(len(tt.writer)))
		l, err := v.Write([]byte(tt.writer))
		if tt.result {
			c.Assert(l, Equals, len(tt.writer))
			c.Assert(err, IsNil)
		}
		c.Assert(v.Equal(), Equals, tt.result)
	}
}

type shortReader struct {
	content *bytes.Buffer
}

func (r *shortReader) Read(buf []byte) (int, error) {
	return r.content.Read(buf[:1])
}

// TestShortRead tests the Verifier in cases when a Read call returns less than
// the requested number of bytes.
func (s *VerifierSuite) TestShortRead(c *C) {
	in := "foo"
	r := &shortReader{content: bytes.NewBufferString(in)}
	v := NewVerifier(r, int64(len(in)))
	l, err := v.Write([]byte(in))
	c.Assert(l, Equals, len(in))
	c.Assert(err, IsNil)
	c.Assert(v.Equal(), Equals, true)
}

func (s *VerifierSuite) TestMultiWrite(c *C) {
	in := "foobarbaz"
	r := bytes.NewBufferString(in)
	v := NewVerifier(r, int64(len(in)))
	l, err := v.Write([]byte("foo"))
	c.Assert(l, Equals, len("foo"))
	c.Assert(err, IsNil)
	l, err = v.Write([]byte("barbaz"))
	c.Assert(l, Equals, len("barbaz"))
	c.Assert(err, IsNil)
	c.Assert(v.Equal(), Equals, true)
}
