package main

import (
	"time"

	"github.com/mxk/go-imap/imap"
)

// IMAPWalker provides support for traversing mails of an IMAP mailbox.
type IMAPWalker struct {
	*IMAPConnection
	callbackFunc IMAPWalkerCallback
}

// IMAPWalkerCallback is the type for the IMAPWalker callback parameter
type IMAPWalkerCallback func([]byte) error

// IMAP date format (rfc3501)
const IMAPDateFormat = "_2-Jan-2006"

// The duration of 30 days
const Month = 30 * 24 * time.Hour

// NewIMAPWalker returns a new IMAPWalker instance.
func NewIMAPWalker() *IMAPWalker {
	return &IMAPWalker{
		IMAPConnection: NewIMAPConnection(),
	}
}

// Walk traverses the given mailbox, filters the results by the currently static
// search filter and invokes the callback for each message.
func (w *IMAPWalker) Walk(mailbox string, callbackFunc IMAPWalkerCallback) error {
	w.callbackFunc = callbackFunc
	logger.Debugf("selecting mailbox '%s'", mailbox)
	_, err := w.conn.Select(mailbox, false /* readonly */)
	if err != nil {
		logger.Errorf("failed to select mailbox: %s", err)
		return err
	}
	date := time.Now().Add(-Month)
	dateStr := date.Format(IMAPDateFormat)
	searchFilter := ("SEEN UNFLAGGED (NOT HEADER X-Lemoncrypt \"\") " +
		"(OR SENTBEFORE " + dateStr + " BEFORE " + dateStr + ")")
	logger.Debugf("searching for: %s", searchFilter)
	cmd, err := imap.Wait(w.conn.Search(searchFilter))
	if err != nil {
		logger.Errorf("search failed: %s", err)
		return err
	}
	logger.Debugf("found %d result sets", len(cmd.Data))
	for idx, rsp := range cmd.Data {
		results := rsp.SearchResults()
		logger.Debugf("result set #%d contains %d results", idx, len(results))
		_ = w.fetchUIDs(results)
	}
	return nil
}

// fetchUIDs downloads the messages with the given UIDs and invokes the callback for
// each message.
func (w *IMAPWalker) fetchUIDs(uid []uint32) error {
	set, _ := imap.NewSeqSet("")
	set.AddNum(uid...)
	cmd, err := w.conn.Fetch(set, "RFC822", "UID")
	if err != nil {
		logger.Errorf("FETCH failed: %s", err)
		return err
	}
	for cmd.InProgress() {
		w.conn.Recv(-1)
		for _, rsp := range cmd.Data {
			_ = w.invokeMessageCallback(rsp)
		}
		cmd.Data = nil

		// Consume other server data
		for _ = range w.conn.Data {
		}
		w.conn.Data = nil
	}
	return nil
}

// invokeMessageCallback extracts the relevant data from the passed FETCH response
// and invokes the user-provided callback.
func (w *IMAPWalker) invokeMessageCallback(rsp *imap.Response) error {
	msgInfo := rsp.MessageInfo()
	logger.Debugf("handling mail uid=%d", msgInfo.Attrs["UID"])
	mailBytes := imap.AsBytes(msgInfo.Attrs["RFC822"])
	logger.Debugf("invoking callback")
	err := w.callbackFunc(mailBytes)
	logger.Debugf("callback completed")
	if err != nil {
		logger.Warningf("callback failed: %s", err)
		return err
	}
	return nil
}
