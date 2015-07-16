package main

import "time"

// Config defines the structure of the TOML config file and represents the
// stored values.
type Config struct {
	Server struct {
		Address  string
		Username string
		Password string
	}
	Mailbox struct {
		Folders           map[string]string
		DeletePlainCopies bool
		OnlyOlderThanDays time.Duration
	}
	PGP struct {
		EncryptionKeyPath       string
		EncryptionKeyID         string `toml:"encryption_key_id"`
		EncryptionKeyPassphrase string
		SigningKeyPath          string
		SigningKeyID            string `toml:"signing_key_id"`
		SigningKeyPassphrase    string
		PlainHeaders            []string
	}
}
