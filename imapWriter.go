package main

import (
	"time"

	"github.com/mxk/go-imap/imap"
)

// IMAPWriter provides support for writing mails to an IMAP mailbox.
type IMAPWriter struct {
	*IMAPConnection
}

// NewIMAPWriter returns a new IMAPWriter instance.
func NewIMAPWriter() *IMAPWriter {
	return &IMAPWriter{
		IMAPConnection: NewIMAPConnection(),
	}
}

func (w *IMAPWriter) SelectMailbox(mailbox string) error {
	logger.Debugf("blindly creating mailbox '%s'", mailbox)
	_, err := imap.Wait(w.conn.Create(mailbox))
	logger.Debugf("mailbox creation ended with err=%s", err)
	logger.Debugf("selecting mailbox '%s'", mailbox)
	_, err = imap.Wait(w.conn.Select(mailbox, false /* readonly=false */))
	if err != nil {
		logger.Errorf("unable to select mailbox '%s': %s", mailbox, err)
	}
	return err
}

func (w *IMAPWriter) Append(mailbox string, flags imap.FlagSet, idate *time.Time, msg imap.Literal) error {
	logger.Debugf("appending mail to mailbox '%s'", mailbox)
	_, err := imap.Wait(w.conn.Append(mailbox, flags, idate, msg))
	if err != nil {
		logger.Errorf("failed to store message: %s", err)
	}
	return err
}
