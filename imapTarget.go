package main

import (
	"time"

	"github.com/mxk/go-imap/imap"
)

// IMAPTarget provides support for writing mails to an IMAP mailbox.
type IMAPTarget struct {
	*IMAPConnection
	curMailbox string
}

// NewIMAPTarget returns a new IMAPTarget instance.
func NewIMAPTarget() *IMAPTarget {
	return &IMAPTarget{
		IMAPConnection: NewIMAPConnection(),
	}
}

// SelectMailbox sets up the IMAP connection to use the given mailbox name.
func (w *IMAPTarget) SelectMailbox(mailbox string) error {
	w.curMailbox = mailbox
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

// Append adds the given message to the given mailbox with the given flags and internal
// date.
func (w *IMAPTarget) Append(flags imap.FlagSet, idate *time.Time, msg imap.Literal) error {
	logger.Debugf("appending mail to mailbox '%s'", w.curMailbox)
	delete(flags, "\\Recent")
	_, err := imap.Wait(w.conn.Append(w.curMailbox, flags, idate, msg))
	if err != nil {
		logger.Errorf("failed to store message: %s", err)
	}
	return err
}
