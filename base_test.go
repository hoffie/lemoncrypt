package main

import (
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	TestingT(t)
}

type BaseSuite struct{}

var _ = Suite(&BaseSuite{})

func (s *BaseSuite) Test(c *C) {
}
