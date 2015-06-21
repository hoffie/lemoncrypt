package main

import (
	"crypto/tls"

	"github.com/mxk/go-imap/imap"
)

type IMAPConnection struct {
	Address  string
	Username string
	Password string
	conn     *imap.Client
}

func (c *IMAPConnection) Init() error {
	logger.Debugf("connecting to %s", c.Address)
	//FIXME support starttls
	tlsConfig := &tls.Config{}
	var err error
	c.conn, err = imap.DialTLS(c.Address, tlsConfig)
	if err != nil {
		logger.Errorf("failed to connect: %s", err)
		return err
	}
	logger.Debugf("connected successfully")

	logger.Debugf("attempting to login as %s", c.Username)
	_, err = imap.Wait(c.conn.Login(c.Username, c.Password))
	if err != nil {
		logger.Errorf("login failed: %s", err)
		return err
	}
	logger.Debugf("logged in")
	return nil
}

func (c *IMAPConnection) Walk(mailbox string) error {
	c.conn.Select(mailbox, true)
	set, err := imap.NewSeqSet("1:*")
	if err != nil {
		logger.Errorf("failed to create SeqSet")
		return err
	}
	cmd, err := c.conn.Fetch(set, "RFC822")
	if err != nil {
		logger.Errorf("FETCH failed: %s", err)
		return err
	}
	for cmd.InProgress() {
		c.conn.Recv(-1)
		for _, rsp := range cmd.Data {
			mail := imap.AsBytes(rsp.MessageInfo().Attrs["RFC822"])
			logger.Infof("mail: %v", string(mail))
		}
		cmd.Data = nil

		// Consume other server data
		for _, _ = range c.conn.Data {
		}
		c.conn.Data = nil
	}
	return nil
}

func (c *IMAPConnection) Close() error {
	logger.Debugf("logging out")
	_, err := c.conn.Logout(0)
	return err
}
