// Package totp generates TOTP codes like the official clients: raw base32
// secrets, otpauth:// URIs (digits, period, algorithm) and steam:// secrets.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const steamChars = "23456789BCDFGHJKMNPQRTVWXY"

// Params describe a TOTP configuration.
type Params struct {
	Secret    []byte
	Digits    int
	Period    int
	Algorithm string
	Steam     bool
}

// Parse decodes a stored TOTP value.
func Parse(key string) (*Params, error) {
	p := &Params{Digits: 6, Period: 30, Algorithm: "sha1"}
	secret := strings.TrimSpace(key)
	lower := strings.ToLower(secret)
	switch {
	case strings.HasPrefix(lower, "otpauth://"):
		u, err := url.Parse(secret)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		if d, err := strconv.Atoi(q.Get("digits")); err == nil && d > 0 && d <= 10 {
			p.Digits = d
		}
		if per, err := strconv.Atoi(q.Get("period")); err == nil && per > 0 {
			p.Period = per
		}
		if a := strings.ToLower(q.Get("algorithm")); a == "sha256" || a == "sha512" || a == "sha1" {
			p.Algorithm = a
		}
		if u.Host == "totp" && strings.Contains(strings.ToLower(u.Path), "steam") || strings.EqualFold(q.Get("encoder"), "steam") {
			p.Steam = true
		}
		secret = q.Get("secret")
	case strings.HasPrefix(lower, "steam://"):
		p.Steam = true
		secret = secret[len("steam://"):]
	}
	if p.Steam {
		p.Digits = 5
	}
	b, err := decodeBase32(secret)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, errors.New("empty TOTP secret")
	}
	p.Secret = b
	return p, nil
}

func decodeBase32(s string) ([]byte, error) {
	s = strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(s))
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

// Code returns the code for time t.
func (p *Params) Code(t time.Time) string {
	var h func() hash.Hash
	switch p.Algorithm {
	case "sha256":
		h = sha256.New
	case "sha512":
		h = sha512.New
	default:
		h = sha1.New
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t.Unix()/int64(p.Period)))
	m := hmac.New(h, p.Secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0xf
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	if p.Steam {
		out := make([]byte, p.Digits)
		for i := range out {
			out[i] = steamChars[bin%uint32(len(steamChars))]
			bin /= uint32(len(steamChars))
		}
		return string(out)
	}
	mod := uint64(1)
	for range p.Digits {
		mod *= 10
	}
	code := strconv.FormatUint(uint64(bin)%mod, 10)
	for len(code) < p.Digits {
		code = "0" + code
	}
	return code
}

// Generate parses key and returns the current code.
func Generate(key string) (string, error) {
	p, err := Parse(key)
	if err != nil {
		return "", err
	}
	return p.Code(time.Now()), nil
}
