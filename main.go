package main

import (
	"os"

	"github.com/codegangsta/cli"
	"github.com/juju/loggo"
)

// logger is this package's global logger.
var logger = loggo.GetLogger("main")

// main entry point.
func main() {
	setupLogging()
	setupCLI()
}

// setupLogging initializes the global logging parameters.
// Log levels can be overriden using the LEMONCRYPT_LOGGING environment variable.
func setupLogging() {
	config := os.Getenv("LEMONCRYPT_LOGGING")
	if config == "" {
		config = "<root>=DEBUG"
	}
	loggo.ConfigureLoggers(config)
	logger.Tracef("logging set up")
}

// setupCLI initializes the command line parser and passes control to it.
// The command line parser is then responsible for invoking specific actions.
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
