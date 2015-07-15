package main

import (
	"bytes"
	"errors"
	"io/ioutil"
	"os"
	"reflect"
	"time"

	"github.com/codegangsta/cli"
	"github.com/mxk/go-imap/imap"
	"github.com/naoina/toml"
)

// EncryptAction provides the context for the default encrypt action.
type EncryptAction struct {
	ctx     *cli.Context
	cfg     *Config
	source  *IMAPSource
	target  *IMAPTarget
	pgp     *PGPTransformer
	metrics *MetricCollector
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

	err = a.setupMetrics()
	if err != nil {
		os.Exit(1)
	}

	err = a.encryptMails()
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
	if len(a.cfg.Mailbox.Folders) < 1 {
		return errors.New("no folders configured (mailbox.folders)")
	}
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

	return a.target.Login(a.cfg.Server.Username, a.cfg.Server.Password)
}

// setupPGP initializes the PGP message converter.
func (a *EncryptAction) setupPGP() error {
	a.pgp = NewPGPTransformer(a.cfg.PGP.PlainHeaders)
	err := a.pgp.LoadEncryptionKey(a.cfg.PGP.EncryptionKeyPath, a.cfg.PGP.EncryptionKeyID,
		a.cfg.PGP.EncryptionKeyPassphrase)
	if err != nil {
		logger.Errorf("failed to load encryption key: %s", err)
		return err
	}

	err = a.pgp.LoadSigningKey(a.cfg.PGP.SigningKeyPath, a.cfg.PGP.SigningKeyID,
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
func (a *EncryptAction) closeTarget() error {
	return a.target.Close()
}

// setupMetrics initializes the metrics collector if the --write-metrics
// command line parameter is given.
func (a *EncryptAction) setupMetrics() error {
	outfile := a.ctx.String("write-metrics")
	if outfile == "" {
		return nil
	}
	logger.Debugf("initializing metrics collector with target='%s'", outfile)
	var err error
	a.metrics, err = NewMetricCollector(outfile)
	if err != nil {
		logger.Errorf("fail to initialize metrics collector: %s", err)
	}
	return err
}

// encryptMails starts iterating over the all configured folders' mails and
// invokes the callback.
func (a *EncryptAction) encryptMails() error {
	for sourceFolder, targetFolder := range a.cfg.Mailbox.Folders {
		if targetFolder == "" {
			targetFolder = sourceFolder
		}
		logger.Infof("working on folder=%s (target=%s)", sourceFolder, targetFolder)
		err := a.target.SelectMailbox(targetFolder)
		if err != nil {
			logger.Errorf("failed to select mailbox %s", targetFolder)
			return err
		}
		err = a.source.Iterate(sourceFolder, a.encryptMail)
		if err != nil {
			logger.Errorf("folder iteration failed")
			return err
		}
	}
	return nil
}

// encryptMail is called for each message, handles transformation and writes the result
// to the target mailbox.
// FIXME: refactoring candidate
func (a *EncryptAction) encryptMail(flags imap.FlagSet, idate *time.Time, origMail imap.Literal) error {
	metricRecord := a.metrics.NewRecord()
	metricRecord.OrigSize = origMail.Info().Len
	metricRecord.Success = false
	defer func() {
		err := metricRecord.Commit()
		if err != nil {
			logger.Warningf("failed to write metric record: %s", err)
		}
	}()

	e, err := a.pgp.NewEncryptor()
	if err != nil {
		return err
	}
	_, err = origMail.WriteTo(e)
	if err != nil {
		return err
	}
	encBytes, err := e.GetBytes()
	if err != nil {
		return err
	}
	encMail := imap.NewLiteral(encBytes)
	metricRecord.ResultSize = encMail.Info().Len
	d := a.pgp.NewDecryptor()
	_, err = encMail.WriteTo(d)
	decBytes, err := d.GetBytes()
	if err != nil {
		return err
	}
	origBuffer := &bytes.Buffer{}
	_, err = origMail.WriteTo(origBuffer)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(origBuffer.Bytes(), decBytes) {
		return errors.New("round-trip verification failed")
	}
	logger.Infof("round-trip verification succeeded")
	metricRecord.Success = true
	return a.target.Append(flags, idate, encMail)
}
