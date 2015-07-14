package main

import (
	"io/ioutil"

	. "gopkg.in/check.v1"
)

type HeaderBufferSuite struct{}

var _ = Suite(&HeaderBufferSuite{})

var headerBufferTests = []struct {
	in  []byte
	out []byte
}{
	{[]byte("Foo: Bar\n\n"), []byte("Foo: Bar\n\n")},
	{[]byte("Foo: Bar\r\n\r\n"), []byte("Foo: Bar\n\n")},
	{[]byte("Foo: Bar\nBaz: y\n\nTrailing"), []byte("Foo: Bar\nBaz: y\n\n")},
	{[]byte("Received foo bar no colon\nFoo: Bar\nBaz: y\n\nTrailing"), []byte("Foo: Bar\nBaz: y\n\n")},
	{[]byte("Foo: Bar,\n Baz\n\nTrailing"), []byte("Foo: Bar,\n Baz\n\n")},
	{[]byte("Foo: Bar,\n\tBaz\n\nTrailing"), []byte("Foo: Bar,\n\tBaz\n\n")},
}

func (s *HeaderBufferSuite) Test(c *C) {
	for _, tt := range headerBufferTests {
		hb := NewHeaderBuffer()
		l, err := hb.Write(tt.in)
		c.Assert(err, IsNil)
		c.Assert(l, Equals, len(tt.in))
		data, err := ioutil.ReadAll(hb)
		c.Assert(err, IsNil)
		c.Assert(data, DeepEquals, tt.out)
	}
}

func (s *HeaderBufferSuite) TestIncomplete(c *C) {
	hb := NewHeaderBuffer()
	in := []byte("Foo: Bar")
	l, err := hb.Write(in)
	c.Assert(err, IsNil)
	c.Assert(l, Equals, len(in))
	data, err := ioutil.ReadAll(hb)
	c.Assert(err, Not(IsNil))
	c.Assert(data, DeepEquals, []byte{})
}
