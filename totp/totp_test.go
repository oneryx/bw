package totp

import (
	"testing"
	"time"
)

// RFC 6238 Appendix B test vectors (8 digits).
func TestRFC6238(t *testing.T) {
	cases := []struct {
		unix int64
		algo string
		uri  string
		want string
	}{
		{59, "sha1", "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8", "94287082"},
		{1111111109, "sha1", "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8", "07081804"},
		{1234567890, "sha256", "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&digits=8&algorithm=SHA256", "91819424"},
		{2000000000, "sha512", "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA&digits=8&algorithm=SHA512", "38618901"},
	}
	for _, c := range cases {
		p, err := Parse(c.uri)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.Code(time.Unix(c.unix, 0)); got != c.want {
			t.Errorf("%s @%d: got %s want %s", c.algo, c.unix, got, c.want)
		}
	}
}

func TestPlainAndSteam(t *testing.T) {
	p, err := Parse("jbsw y3dp ehpk 3pxp")
	if err != nil || p.Digits != 6 || p.Period != 30 {
		t.Fatalf("plain parse: %+v %v", p, err)
	}
	s, err := Parse("steam://JBSWY3DPEHPK3PXP")
	if err != nil || !s.Steam {
		t.Fatalf("steam parse: %v", err)
	}
	code := s.Code(time.Unix(1700000000, 0))
	if len(code) != 5 {
		t.Fatalf("steam code %q", code)
	}
	for _, r := range code {
		if !contains(steamChars, r) {
			t.Fatalf("bad steam char in %q", code)
		}
	}
}

func contains(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}
