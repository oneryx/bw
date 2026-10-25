// Package wordlist embeds the EFF long wordlist used by the official clients
// for passphrases and fingerprint phrases.
package wordlist

import (
	_ "embed"
	"strings"
)

//go:embed eff_long.txt
var raw string

// EFFLong is the 7776-word EFF long wordlist, in the official order.
var EFFLong = strings.Fields(raw)
