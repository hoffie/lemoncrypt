package main

import (
	"io/ioutil"
	"os"
	"time"

	"github.com/codegangsta/cli"
	"github.com/juju/loggo"
	"github.com/mxk/go-imap/imap"
	"github.com/naoina/toml"
)

var logger = loggo.GetLogger("main")

func main() {
	setupLogging()
	setupCLI()
}

func setupLogging() {
	config := os.Getenv("LEMONCRYPT_LOGGING")
	if config == "" {
		config = "<root>=DEBUG"
	}
	loggo.ConfigureLoggers(config)
	logger.Tracef("logging set up")
}

func setupCLI() {
	app := cli.NewApp()
	app.Name = "lemoncrypt"
	app.Usage = "archive and encrypt the messages in your mailbox"
	app.Version = "0.1"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "config",
			Usage:  "path to your config file",
			EnvVar: "LIMECRYPT_CONFIG",
		},
	}
	ea := &EncryptAction{}
	app.Action = ea.Run
	app.Run(os.Args)
}

// EncryptAction provides the context for the default encrypt action.
type EncryptAction struct {
	ctx    *cli.Context
	cfg    *Config
	walker *IMAPWalker
	writer *IMAPWriter
}

// Config defines the structure of the TOML config file and represents the
// stored values.
type Config struct {
	Server struct {
		Address  string
		Username string
		Password string
	}
	Mailbox struct {
		Source string
		Target string
	}
}

// Run starts the EncryptAction.
func (a *EncryptAction) Run(ctx *cli.Context) {
	a.ctx = ctx
	err := a.loadConfig()
	if err != nil {
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

func (a *EncryptAction) closeWalkerServer() error {
	return a.walker.Close()
}

func (a *EncryptAction) closeWriterServer() error {
	return a.walker.Close()
}

func (a *EncryptAction) callback(flags imap.FlagSet, idate *time.Time, mail imap.Literal) error {
	return a.writer.Append(a.cfg.Mailbox.Target, flags, idate, mail)
}

func (a *EncryptAction) process() error {
	return a.walker.Walk(a.cfg.Mailbox.Source, a.callback)
}
