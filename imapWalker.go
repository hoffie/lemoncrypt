package main

import (
	"time"

	"github.com/mxk/go-imap/imap"
)

// IMAPWalker provides support for traversing mails of an IMAP mailbox.
type IMAPWalker struct {
	*IMAPConnection
	callbackFunc IMAPWalkerCallback
	deletionSet  *imap.SeqSet
}

// IMAPWalkerCallback is the type for the IMAPWalker callback parameter
type IMAPWalkerCallback func(imap.FlagSet, *time.Time, imap.Literal) error

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
	_, err := w.conn.Select(mailbox, false /* read-write */)
	if err != nil {
		logger.Errorf("failed to select mailbox: %s", err)
		return err
	}
	date := time.Now().Add(-Month)
	dateStr := date.Format(IMAPDateFormat)
	searchFilter := ("UNDELETED SEEN UNFLAGGED (NOT HEADER X-Lemoncrypt \"\") " +
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
	logger.Debugf("finally removing mail marked for deletion")
	_, err = imap.Wait(w.conn.Expunge(nil))
	if err != nil {
		logger.Errorf("failed to remove mail marked for deletion: %s", err)
	}
	return err
}

// fetchUIDs downloads the messages with the given UIDs and invokes the callback for
// each message.
func (w *IMAPWalker) fetchUIDs(uid []uint32) error {
	set, _ := imap.NewSeqSet("")
	set.AddNum(uid...)
	w.deletionSet, _ = imap.NewSeqSet("")
	cmd, err := w.conn.Fetch(set, "RFC822", "UID", "FLAGS", "INTERNALDATE")
	if err != nil {
		logger.Errorf("FETCH failed: %s", err)
		return err
	}
	for cmd.InProgress() {
		w.conn.Recv(-1)
		for _, rsp := range cmd.Data {
			_ = w.handleMessage(rsp)
		}
		cmd.Data = nil

		// Consume other server data
		for _ = range w.conn.Data {
		}
		w.conn.Data = nil
	}

	if rsp, err := cmd.Result(imap.OK); err != nil {
		if err == imap.ErrAborted {
			logger.Errorf("FETCH command aborted")
		} else {
			logger.Errorf("FETCH error: %s", rsp.Info)
		}
	} else {
		logger.Debugf("FETCH completed without errors")
	}

	logger.Debugf("marking mails as deleted")
	_, err = imap.Wait(w.conn.Store(set, "+FLAGS.SILENT", "(\\Deleted)"))
	if err != nil {
		logger.Errorf("failed to mark uid=%d for deletion: %s", uid, err)
	}
	return err
}

// handleMessage processes one message, invokes the callback and deletes it on
// success.
func (w *IMAPWalker) handleMessage(rsp *imap.Response) error {
	msgInfo := rsp.MessageInfo()
	err := w.invokeMessageCallback(msgInfo)
	if err != nil {
		return err
	}
	uid := imap.AsNumber(msgInfo.Attrs["UID"])
	logger.Debugf("saving message uid=%d for deletion", uid)
	w.deletionSet.AddNum(uid)
	return err
}

// invokeMessageCallback extracts the relevant data from the passed FETCH response
// and invokes the user-provided callback.
func (w *IMAPWalker) invokeMessageCallback(msgInfo *imap.MessageInfo) error {
	logger.Debugf("handling mail uid=%d", msgInfo.Attrs["UID"])
	flags := imap.AsFlagSet(msgInfo.Attrs["FLAGS"])
	idate := imap.AsDateTime(msgInfo.Attrs["INTERNALDATE"])
	mailBytes := imap.AsBytes(msgInfo.Attrs["RFC822"])
	mailLiteral := imap.NewLiteral(mailBytes)
	logger.Debugf("invoking callback")
	err := w.callbackFunc(flags, &idate, mailLiteral)
	if err == nil {
		logger.Debugf("callback successful")
	} else {
		logger.Warningf("callback failed: %s", err)
	}
	return err
}
