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
	walker *IMAPWalker
	writer *IMAPWriter
	pgp    *PGPWriter
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

	err = a.setupWalkerServer()
	if err != nil {
		os.Exit(1)
	}
	defer a.closeWalkerServer()

	err = a.setupWriterServer()
	if err != nil {
		os.Exit(1)
	}
	defer a.closeWriterServer()

	err = a.setupPGP()
	if err != nil {
		os.Exit(1)
	}

	err = a.process()
	if err != nil {
		os.Exit(1)
	}
}

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

func (a *EncryptAction) validateConfig() error {
	if a.cfg.PGP.EncryptionKeyPath == "" {
		return errors.New("missing encryption key path")
	}
	return nil
}

func (a *EncryptAction) setupWalkerServer() error {
	a.walker = NewIMAPWalker()
	err := a.walker.Dial(a.cfg.Server.Address)
	if err != nil {
		return err
	}
	return a.walker.Login(a.cfg.Server.Username, a.cfg.Server.Password)
}

func (a *EncryptAction) setupWriterServer() error {
	a.writer = NewIMAPWriter()
	err := a.writer.Dial(a.cfg.Server.Address)
	if err != nil {
		return err
	}

	err = a.writer.Login(a.cfg.Server.Username, a.cfg.Server.Password)
	if err != nil {
		return err
	}

	return a.writer.SelectMailbox(a.cfg.Mailbox.Target)
}

func (a *EncryptAction) setupPGP() error {
	a.pgp = NewPGPWriter()
	err := a.pgp.LoadEncryptionKey(a.cfg.PGP.EncryptionKeyPath)
	if err != nil {
		logger.Errorf("failed to load encryption key: %s", err)
		return err
	}
	err = a.pgp.LoadSigningKey(a.cfg.PGP.SigningKeyPath,
		a.cfg.PGP.SigningKeyPassphrase)
	if err != nil {
		logger.Errorf("failed to load signing key: %s", err)
		return err
	}
	return nil
}

func (a *EncryptAction) closeWalkerServer() error {
	return a.walker.Close()
}

func (a *EncryptAction) closeWriterServer() error {
	return a.walker.Close()
}

func (a *EncryptAction) callback(flags imap.FlagSet, idate *time.Time, mail imap.Literal) error {
	err := a.pgp.Reset()
	if err != nil {
		return err
	}
	_, err = mail.WriteTo(a.pgp)
	if err != nil {
		return err
	}
	bytes, err := a.pgp.GetBytes()
	if err != nil {
		return err
	}
	encMail := imap.NewLiteral(bytes)
	return a.writer.Append(a.cfg.Mailbox.Target, flags, idate, encMail)
}

func (a *EncryptAction) process() error {
	return a.walker.Walk(a.cfg.Mailbox.Source, a.callback)
}
