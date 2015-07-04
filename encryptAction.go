package main

import (
	"errors"
	"io/ioutil"
	"os"
	"time"

	"github.com/codegangsta/cli"
	"github.com/mxk/go-imap/imap"
	"github.com/naoina/toml"
)

// EncryptAction provides the context for the default encrypt action.
type EncryptAction struct {
	ctx    *cli.Context
	cfg    *Config
	source *IMAPSource
	target *IMAPTarget
	pgp    *PGPTransformer
}

// Run starts the EncryptAction.
func (a *EncryptAction) Run(ctx *cli.Context) {
	a.ctx = ctx
	err := a.loadConfig()
	if err != nil {
		os.Exit(1)
	}

	err = a.validateConfig()
	if err != nil {
		logger.Errorf("config validation failed: %s", err)
		os.Exit(1)
	}

	err = a.setupSource()
	if err != nil {
		os.Exit(1)
	}
	defer a.closeSource()

	err = a.setupTarget()
	if err != nil {
		os.Exit(1)
	}
	defer a.closeTarget()

	err = a.setupPGP()
	if err != nil {
		os.Exit(1)
	}

	err = a.process()
	if err != nil {
		os.Exit(1)
	}
}

// loadConfig reads and parses the config file.
// If no error occurs, the config is available in the EncryptAction.cfg field
// afterwards.
func (a *EncryptAction) loadConfig() error {
	path := a.ctx.String("config")
	if path == "" {
		path = "lemoncrypt.cfg"
	}

	logger.Debugf("trying to load config file %s", path)
	content, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Errorf("failed to read config file: %s", err)
		return err
	}

	a.cfg = &Config{}
	err = toml.Unmarshal(content, a.cfg)
	if err != nil {
		logger.Errorf("unable to parse config file: %s", err)
		return err
	}

	logger.Debugf("config loaded successfully")
	return nil
}

// validateConfig performs basic upfront sanity checks on certain config values and
// returns an error on failure.
func (a *EncryptAction) validateConfig() error {
	if a.cfg.PGP.EncryptionKeyPath == "" {
		return errors.New("missing encryption key path")
	}
	if len(a.cfg.PGP.PlainHeaders) == 0 {
		a.cfg.PGP.PlainHeaders = []string{
			"From", "To", "Cc", "Bcc", "Date", "Subject"}
	}

	a.cfg.PGP.EncryptionKeyPath = expandTilde(a.cfg.PGP.EncryptionKeyPath)
	a.cfg.PGP.SigningKeyPath = expandTilde(a.cfg.PGP.SigningKeyPath)
	return nil
}

// setupSource initializes the source IMAP connection.
func (a *EncryptAction) setupSource() error {
	a.source = NewIMAPSource()
	err := a.source.Dial(a.cfg.Server.Address)
	if err != nil {
		return err
	}
	return a.source.Login(a.cfg.Server.Username, a.cfg.Server.Password)
}

// setupTarget initializes the target IMAP connection.
func (a *EncryptAction) setupTarget() error {
	a.target = NewIMAPTarget()
	err := a.target.Dial(a.cfg.Server.Address)
	if err != nil {
		return err
	}

	err = a.target.Login(a.cfg.Server.Username, a.cfg.Server.Password)
	if err != nil {
		return err
	}

	return a.target.SelectMailbox(a.cfg.Mailbox.Target)
}

// setupPGP initializes the PGP message converter.
func (a *EncryptAction) setupPGP() error {
	a.pgp = NewPGPTransformer(a.cfg.PGP.PlainHeaders)
	err := a.pgp.LoadEncryptionKey(a.cfg.PGP.EncryptionKeyPath, a.cfg.PGP.EncryptionKeyId)
	if err != nil {
		logger.Errorf("failed to load encryption key: %s", err)
		return err
	}

	err = a.pgp.LoadSigningKey(a.cfg.PGP.SigningKeyPath, a.cfg.PGP.SigningKeyId,
		a.cfg.PGP.SigningKeyPassphrase)
	if err != nil {
		logger.Errorf("failed to load signing key: %s", err)
		return err
	}

	return nil
}

// closeSource cleans up the source server connection.
func (a *EncryptAction) closeSource() error {
	return a.source.Close()
}

// closeTarget cleans up the target server connection.
// FIXME: rename?
func (a *EncryptAction) closeTarget() error {
	return a.target.Close()
}

// callback is called for each message, handles transformation and writes the result
// to the target mailbox.
// FIXME rename
func (a *EncryptAction) callback(flags imap.FlagSet, idate *time.Time, mail imap.Literal) error {
	e, err := a.pgp.NewEncryptor()
	if err != nil {
		return err
	}
	_, err = mail.WriteTo(e)
	if err != nil {
		return err
	}
	bytes, err := e.GetBytes()
	if err != nil {
		return err
	}
	encMail := imap.NewLiteral(bytes)
	return a.target.Append(a.cfg.Mailbox.Target, flags, idate, encMail)
}

// process starts iterating over the source mailbox's mails and invokes the callback
// FIXME rename
func (a *EncryptAction) process() error {
	return a.source.Iterate(a.cfg.Mailbox.Source, a.callback)
}
