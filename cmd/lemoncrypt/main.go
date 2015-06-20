package main

import (
	"os"
	"io/ioutil"

	"github.com/juju/loggo"
	"github.com/codegangsta/cli"
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
	app.Flags = []cli.Flag {
		cli.StringFlag{
			Name: "config",
			Usage: "path to your config file",
			EnvVar: "LIMECRYPT_CONFIG",
		},
	}
	ea := &EncryptAction{}
	app.Action = ea.Run
	app.Run(os.Args)
}

type EncryptAction struct {
	ctx *cli.Context
	cfg *Config
}

type Config struct {
	Server struct {
		Host string
		Username string
		Password string
	}
}

func (a *EncryptAction) Run(ctx *cli.Context) {
	a.ctx = ctx
	a.loadConfig()
}

func (a *EncryptAction) loadConfig() {
	path := a.ctx.String("config")
	if path == "" {
		path = "lemoncrypt.cfg"
	}
	logger.Debugf("trying to load config file %s", path)
	content, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Errorf("failed to read config file: %s", err)
		os.Exit(1)
	}
	a.cfg = &Config{}
	err = toml.Unmarshal(content, a.cfg)
	if err != nil {
		logger.Errorf("unable to parse config file: %s", err)
		os.Exit(1)
	}
	logger.Debugf("config loaded successfully")
}
