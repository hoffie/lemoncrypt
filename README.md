# lemoncrypt
lemoncrypt retroactively encrypts your IMAP mailbox using PGP/MIME in a reversible way.
It runs on your local desktop machine and does not need any special permissions.

Should you ever decide that you want to stop using PGP/MIME, you could even restore the original state
in a bit-perfect manner.

## Project status
Although lots of safety measures are in place (such as round-trip verification) and lots of real-world emails have
been processed by this tool (over 600.000), special care should be taken when running the tool against real mailboxes.
Always keep recent backups around!

## Platforms
Until now, lemoncrypt has only been tested on Linux; in theory it should run on other go-supported systems as well.

## Prerequisites
- An ordinary PGP key as the encryption target.
- A new, independent PGP key/pair for signing.
- A PGP/MIME-aware email client such as Thunderbird/Enigmail, KMail or similar.

## Installation
`go get github.com/hoffie/lemoncrypt`

## Configuration
See [lemoncrypt.cfg.example](lemoncrypt.cfg.example)

## Usage
`./lemoncrypt`
Note: lemoncrypt will only encrypt emails, which are older than 30 days, have been marked as read and are not starred.
This will become adjustable in the future.

## License
lemoncrypt is distributed under the [AGPL license](LICENSE.AGPL)

## Author
This project was initially created by Christian Hoffmann (@hoffie).
