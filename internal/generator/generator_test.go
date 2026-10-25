package generator

import (
	"strings"
	"testing"
	"unicode"
)

func TestPasswordConstraints(t *testing.T) {
	for range 200 {
		p := Password(PasswordOptions{Length: 20, Uppercase: true, Lowercase: true, Number: true, Special: true, MinNumber: 3, MinSpecial: 2})
		if len(p) != 20 {
			t.Fatalf("length %d", len(p))
		}
		var up, low, num, sp int
		for _, r := range p {
			switch {
			case unicode.IsUpper(r):
				up++
			case unicode.IsLower(r):
				low++
			case unicode.IsDigit(r):
				num++
			case strings.ContainsRune(special, r):
				sp++
			default:
				t.Fatalf("unexpected char %q", r)
			}
		}
		if up < 1 || low < 1 || num < 3 || sp < 2 {
			t.Fatalf("constraints not met: %s", p)
		}
	}
}

func TestPasswordAvoidAmbiguous(t *testing.T) {
	for range 200 {
		p := Password(PasswordOptions{Length: 64, Uppercase: true, Lowercase: true, Number: true})
		if strings.ContainsAny(p, "IlO01") {
			t.Fatalf("ambiguous char in %s", p)
		}
	}
}

func TestPassphrase(t *testing.T) {
	p := Passphrase(PassphraseOptions{NumWords: 5, Separator: "_", Capitalize: true, IncludeNumber: true})
	words := strings.Split(p, "_")
	if len(words) != 5 {
		t.Fatalf("got %q", p)
	}
	digits := 0
	for _, w := range words {
		if !unicode.IsUpper(rune(w[0])) {
			t.Fatalf("not capitalized: %q", p)
		}
		if unicode.IsDigit(rune(w[len(w)-1])) {
			digits++
		}
	}
	if digits != 1 {
		t.Fatalf("expected exactly one number: %q", p)
	}
}
