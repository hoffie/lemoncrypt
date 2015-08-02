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
// In order to improve performance, we always prefetch one message so that the IMAP
// server action and network transfer can happen while we handle the previous message.
func (w *IMAPSource) fetchIDs(ids []uint32) error {
	var cur *imap.Command
	for idx, id := range ids {
		if idx == 0 {
			var err error
			cur, err = w.startFetch(id)
			if err != nil {
				logger.Errorf("pre-fetch request failed: %s", err)
				return err
			}
			// don't start working on the first message just yet,
			// we pre-fetch the second message in the next loop
			//before we start working.
			continue
		}
		next, err := w.startFetch(id)
		if err != nil {
			logger.Errorf("fetch request failed: %s", err)
			return err
		}
		err = w.handleFetchResult(cur)
		if err != nil {
			logger.Errorf("fetching failed: %s", err)
			return err
		}
		cur = next
	}
	// as our loop is one FETCH ahead, we still have to handle the last message here:
	if cur == nil {
		// loop didn't run
		return nil
	}
	err := w.handleFetchResult(cur)
	if err != nil {
		logger.Errorf("fetching failed in last loop: %s", err)
		return err
	}
	return nil
}

func (w *IMAPSource) startFetch(id uint32) (*imap.Command, error) {
	set, _ := imap.NewSeqSet("")
	set.AddNum(id)
	return w.conn.Fetch(set, "RFC822", "UID", "FLAGS", "INTERNALDATE")
}

func (w *IMAPSource) handleFetchResult(cmd *imap.Command) error {
	cmd, err := imap.Wait(cmd, nil)
	if err != nil {
		return err
	}
	for _, rsp := range cmd.Data {
		// we only fetch one message at a time, so this loop should
		// only run once
		err := w.handleMessage(rsp)
		if err != nil {
			logger.Errorf("handleMessage failed: %s", err)
			return err
		}
	}
	return nil
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
	_, err := imap.Wait(w.conn.UIDStore(set, "+FLAGS", "(\\Deleted)"))
	if err != nil {
		logger.Errorf("failed to mark uid=%d for deletion: %s", uid, err)
		return err
	}
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
