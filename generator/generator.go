// Package generator ports the official password/passphrase generator.
package generator

import (
	"crypto/rand"
	"math/big"
	"strings"

	"github.com/oneryx/bw/internal/wordlist"
)

// PasswordOptions mirrors the CLI generate options for passwords.
type PasswordOptions struct {
	Length     int
	Uppercase  bool
	Lowercase  bool
	Number     bool
	Special    bool
	MinNumber  int
	MinSpecial int
	// Ambiguous allows ambiguous characters (the CLI's --ambiguous flag disables them).
	Ambiguous bool
}

// PassphraseOptions mirrors the CLI generate options for passphrases.
type PassphraseOptions struct {
	NumWords      int
	Separator     string
	Capitalize    bool
	IncludeNumber bool
}

const special = "!@#$%^&*"

type charsets struct{ upper, lower, digit string }

var (
	full         = charsets{"ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", "0123456789"}
	unmistakable = charsets{"ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789"}
)

// Int returns a uniform random integer in [0, n).
func Int(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err)
	}
	return int(v.Int64())
}

func pick(set string) byte { return set[Int(len(set))] }

// Password generates a password: each enabled class contributes its minimum
// count, the remainder is drawn from all enabled classes, then shuffled.
func Password(o PasswordOptions) string {
	cs := unmistakable
	if o.Ambiguous {
		cs = full
	}
	var parts []string
	all := ""
	add := func(enabled bool, min int, set string) {
		if !enabled {
			return
		}
		for range max(min, 0) {
			parts = append(parts, set)
		}
		all += set
	}
	add(o.Uppercase, 1, cs.upper)
	add(o.Lowercase, 1, cs.lower)
	add(o.Number, o.MinNumber, cs.digit)
	add(o.Special, o.MinSpecial, special)
	for range max(o.Length-len(parts), 0) {
		parts = append(parts, all)
	}
	// Fisher-Yates shuffle of the per-position character sets.
	for i := len(parts) - 1; i > 0; i-- {
		j := Int(i + 1)
		parts[i], parts[j] = parts[j], parts[i]
	}
	out := make([]byte, len(parts))
	for i, set := range parts {
		out[i] = pick(set)
	}
	return string(out)
}

// Passphrase generates words from the EFF long wordlist.
func Passphrase(o PassphraseOptions) string {
	lucky := -1
	if o.IncludeNumber {
		lucky = Int(o.NumWords)
	}
	words := make([]string, o.NumWords)
	for i := range words {
		w := wordlist.EFFLong[Int(len(wordlist.EFFLong))]
		if o.Capitalize {
			w = strings.ToUpper(w[:1]) + w[1:]
		}
		if i == lucky {
			w += string(rune('0' + Int(10)))
		}
		words[i] = w
	}
	return strings.Join(words, o.Separator)
}
