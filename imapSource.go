package main

import (
	"time"

	"github.com/mxk/go-imap/imap"
)

// IMAP date format (rfc3501)
const IMAPDateFormat = "_2-Jan-2006"

// IMAPSource provides support for traversing mails of an IMAP mailbox.
type IMAPSource struct {
	*IMAPConnection
	callbackFunc      IMAPSourceCallback
	deletePlainCopies bool
	minAge            time.Duration
	deletionResults   []*imap.Command
}

// IMAPSourceCallback is the type for the IMAPSource callback parameter
type IMAPSourceCallback func(imap.FlagSet, *time.Time, imap.Literal) error

// The duration of a day
const Day = 24 * time.Hour

// NewIMAPSource returns a new IMAPSource instance.
func NewIMAPSource(deletePlainCopies bool, minAgeInDays time.Duration) *IMAPSource {
	return &IMAPSource{
		IMAPConnection:    NewIMAPConnection(),
		deletePlainCopies: deletePlainCopies,
		minAge:            minAgeInDays * Day,
	}
}

// Iterate loops through the given mailbox, filters the results by the currently
// static search filter and invokes the callback for each message.
func (w *IMAPSource) Iterate(mailbox string, callbackFunc IMAPSourceCallback) error {
	w.callbackFunc = callbackFunc
	logger.Debugf("selecting mailbox '%s'", mailbox)
	_, err := w.conn.Select(mailbox, false /* read-write */)
	if err != nil {
		logger.Errorf("failed to select mailbox: %s", err)
		return err
	}
	date := time.Now().Add(-w.minAge)
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
		if len(results) == 0 {
			continue
		}
		_ = w.fetchIDs(results)
	}
	logger.Debugf("finally removing mail marked for deletion")
	_, err = imap.Wait(w.conn.Expunge(nil))
	if err != nil {
		logger.Errorf("failed to remove mail marked for deletion: %s", err)
	}
	return err
}

// fetchIDs downloads the messages with the given IDs and invokes the callback for
// each message.
func (w *IMAPSource) fetchIDs(ids []uint32) error {
	set, _ := imap.NewSeqSet("")
	set.AddNum(ids...)
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
	}

	if rsp, err := cmd.Result(imap.OK); err != nil {
		if err == imap.ErrAborted {
			logger.Errorf("FETCH command aborted")
		} else {
			logger.Errorf("FETCH error: %s", rsp.Info)
		}
		return err
	} else {
		logger.Debugf("FETCH completed without errors")
	}
	for _, cmd := range w.deletionResults {
		rsp, err := cmd.Result(imap.OK)
		if err != nil {
			logger.Warningf("deletion failure: %s, info=%s", err, rsp.Info)
		}
	}
	return err

}

// handleMessage processes one message, invokes the callback and deletes it on
// success.
func (w *IMAPSource) handleMessage(rsp *imap.Response) error {
	msgInfo := rsp.MessageInfo()
	err := w.invokeMessageCallback(msgInfo)
	if err != nil {
		return err
	}
	uid := imap.AsNumber(msgInfo.Attrs["UID"])
	return w.deleteMessage(uid)
}

// deleteMessage marks the message with the given UID for deletion.
func (w *IMAPSource) deleteMessage(uid uint32) error {
	if !w.deletePlainCopies {
		return nil
	}

	logger.Debugf("marking message uid=%d for deletion", uid)
	set, _ := imap.NewSeqSet("")
	set.AddNum(uid)
	cmd, err := w.conn.UIDStore(set, "+FLAGS", "(\\Deleted)")
	if err != nil {
		logger.Errorf("failed to mark uid=%d for deletion: %s", uid, err)
		return err
	}
	w.deletionResults = append(w.deletionResults, cmd)
	return nil
}

// invokeMessageCallback extracts the relevant data from the passed FETCH response
// and invokes the user-provided callback.
func (w *IMAPSource) invokeMessageCallback(msgInfo *imap.MessageInfo) error {
	logger.Debugf("handling mail uid=%d", msgInfo.Attrs["UID"])
	flags := imap.AsFlagSet(msgInfo.Attrs["FLAGS"])
	idate := imap.AsDateTime(msgInfo.Attrs["INTERNALDATE"])
	mailBytes := imap.AsBytes(msgInfo.Attrs["RFC822"])
	mailLiteral := imap.NewLiteral(mailBytes)
	logger.Debugf("invoking message transformer")
	err := w.callbackFunc(flags, &idate, mailLiteral)
	if err == nil {
		logger.Debugf("message transformation successful")
	} else {
		logger.Warningf("message transformation failed: %s", err)
	}
	return err
}
