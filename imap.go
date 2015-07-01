package main

import (
	"crypto/tls"

	"github.com/mxk/go-imap/imap"
)

// IMAPConnection handles an IMAP connection.
type IMAPConnection struct {
	conn *imap.Client
}

// NewIMAPConnection returns a new IMAPConnection instance.
func NewIMAPConnection() *IMAPConnection {
	return &IMAPConnection{}
}

// Dial connects to the given address.
func (c *IMAPConnection) Dial(address string) error {
	logger.Debugf("connecting to %s", address)
	tlsConfig := &tls.Config{}
	var err error
	c.conn, err = imap.DialTLS(address, tlsConfig)
	if err != nil {
		logger.Errorf("failed to connect: %s", err)
		return err
	}

	return nil
}

// Login authenticates with the server using the provided credentials.
func (c *IMAPConnection) Login(username, password string) error {
	logger.Debugf("attempting to login as %s", username)
	_, err := imap.Wait(c.conn.Login(username, password))
	if err != nil {
		logger.Errorf("login failed: %s", err)
		return err
	}
	logger.Debugf("logged in")
	return nil
}

// Close ends the server connection.
//
// Note: Calling this is required to clean up properly.
func (c *IMAPConnection) Close() error {
	logger.Debugf("logging out")
	_, err := c.conn.Logout(0)
	return err
}
