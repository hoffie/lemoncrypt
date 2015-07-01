package main

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
	PGP struct {
		EncryptionKeyPath    string
		SigningKeyPath       string
		SigningKeyPassphrase string
	}
}
