package main

import (
	"io/ioutil"
	"os"

	"github.com/codegangsta/cli"
	"github.com/juju/loggo"
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
	ctx  *cli.Context
	cfg  *Config
	conn *IMAPWalker
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
	err = a.setupServer()
	if err != nil {
		os.Exit(1)
	}

	err = a.process()
	if err != nil {
		os.Exit(1)
	}
	defer a.closeServer()
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

func (a *EncryptAction) setupServer() error {
	a.conn = NewIMAPWalker()
	err := a.conn.Dial(a.cfg.Server.Address)
	if err != nil {
		return err
	}
	return a.conn.Login(a.cfg.Server.Username, a.cfg.Server.Password)
}

func (a *EncryptAction) closeServer() error {
	return a.conn.Close()
}

func (a *EncryptAction) callback(mail []byte) error {
	logger.Infof("callback: %d bytes", len(mail))
	return nil
}

func (a *EncryptAction) process() error {
	return a.conn.Walk(a.cfg.Mailbox.Source, a.callback)
}
