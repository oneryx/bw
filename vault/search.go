package vault

import (
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"golang.org/x/net/publicsuffix"
)

// stripMarks mirrors normalizeSearchQuery: drop combining diacritics and fold
// precomposed Latin letters to their base letter.
func stripMarks(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 0x300 && r <= 0x36f {
			return -1
		}
		if b, ok := diacriticFold[r]; ok {
			return b
		}
		return r
	}, s)
}

// collate approximates Intl.Collator(locale, {numeric: true, sensitivity: "base"}).
func collate(a, b string) int {
	ar, br := []rune(fold(a)), []rune(fold(b))
	i, j := 0, 0
	for i < len(ar) && j < len(br) {
		ca, cb := ar[i], br[j]
		if unicode.IsDigit(ca) && unicode.IsDigit(cb) {
			si := i
			for i < len(ar) && unicode.IsDigit(ar[i]) {
				i++
			}
			sj := j
			for j < len(br) && unicode.IsDigit(br[j]) {
				j++
			}
			na := strings.TrimLeft(string(ar[si:i]), "0")
			nb := strings.TrimLeft(string(br[sj:j]), "0")
			if len(na) != len(nb) {
				return cmpInt(len(na), len(nb))
			}
			if c := strings.Compare(na, nb); c != 0 {
				return c
			}
			continue
		}
		if ca != cb {
			if ra, rb := runeClass(ca), runeClass(cb); ra != rb {
				return cmpInt(ra, rb)
			}
			return cmpInt(int(ca), int(cb))
		}
		i++
		j++
	}
	return cmpInt(len(ar)-i, len(br)-j)
}

// runeClass orders whitespace < punctuation < symbols < digits < letters (ICU root order).
func runeClass(r rune) int {
	switch {
	case unicode.IsSpace(r):
		return 0
	case unicode.IsPunct(r):
		return 1
	case unicode.IsSymbol(r):
		return 2
	case unicode.IsDigit(r):
		return 3
	case unicode.IsLetter(r):
		return 4
	default:
		return 5
	}
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// SortBy sorts items by a name like the official clients (Intl.Collator).
func SortBy[T any](items []T, key func(T) string) {
	slices.SortStableFunc(items, func(a, b T) int { return collate(key(a), key(b)) })
}

// SortCiphers sorts by name, then by username for logins (getLocaleSortingFunction).
func SortCiphers(cs []*Cipher) {
	slices.SortStableFunc(cs, func(a, b *Cipher) int {
		if r := collate(a.Name, b.Name); r != 0 || a.Type != TypeLogin || b.Type != TypeLogin {
			return r
		}
		au, bu := "", ""
		if a.Login != nil && a.Login.Username != nil {
			au = *a.Login.Username
		}
		if b.Login != nil && b.Login.Username != nil {
			bu = *b.Login.Username
		}
		return collate(au, bu)
	})
}

// Subtitle mirrors CipherView.subTitle.
func (c *Cipher) Subtitle() *string {
	switch c.Type {
	case TypeLogin:
		if c.Login == nil {
			return nil
		}
		if (c.Login.Username == nil || *c.Login.Username == "") && len(c.Login.Fido2Credentials) > 0 {
			return c.Login.Fido2Credentials[0].UserName
		}
		return c.Login.Username
	case TypeCard:
		if c.Card == nil {
			return nil
		}
		var s *string
		if c.Card.Brand != nil {
			b := *c.Card.Brand
			s = &b
		}
		if n := c.Card.Number; n != nil && len(*n) >= 4 {
			sub := ""
			if s != nil && *s != "" {
				sub = *s + ", "
			}
			count := 4
			if len(*n) >= 5 && (strings.HasPrefix(*n, "34") || strings.HasPrefix(*n, "37")) {
				count = 5
			}
			sub += "*" + (*n)[len(*n)-count:]
			s = &sub
		}
		return s
	case TypeIdentity:
		if c.Identity == nil || (c.Identity.FirstName == nil && c.Identity.LastName == nil) {
			return nil
		}
		s := ""
		if c.Identity.FirstName != nil {
			s = *c.Identity.FirstName
		}
		if c.Identity.LastName != nil {
			if s != "" {
				s += " "
			}
			s += *c.Identity.LastName
		}
		return &s
	case TypeSSHKey:
		if c.SSHKey == nil {
			return nil
		}
		return c.SSHKey.KeyFingerprint
	}
	return nil
}

// Hostname mirrors Utils.getHostname.
func Hostname(uri string) string {
	u := parseURL(uri)
	if u == nil {
		return ""
	}
	return u.Hostname()
}

// Host mirrors Utils.getHost (hostname with port).
func Host(uri string) string {
	u := parseURL(uri)
	if u == nil {
		return ""
	}
	return u.Host
}

var schemeRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://`)

// parseURL mirrors Utils.getUrl: prefix http:// when no scheme is present.
func parseURL(uri string) *url.URL {
	uri = strings.TrimSpace(uri)
	if uri == "" || strings.HasPrefix(uri, "data:") || strings.HasPrefix(uri, "about:") {
		return nil
	}
	if !schemeRe.MatchString(uri) {
		if !strings.Contains(uri, ".") && !strings.HasPrefix(uri, "localhost") {
			return nil
		}
		uri = "http://" + uri
	}
	u, err := url.Parse(uri)
	if err != nil || u.Host == "" {
		return nil
	}
	return u
}

// Domain mirrors Utils.getDomain (registrable domain, IP or localhost).
func Domain(uri string) string {
	h := Hostname(uri)
	if h == "" {
		return ""
	}
	h = strings.ToLower(h)
	if h == "localhost" || net.ParseIP(h) != nil {
		return h
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err != nil {
		return ""
	}
	return d
}

// SearchCiphers mirrors searchCiphersBasic: every query term must match the
// name, an id prefix (8+ chars), the subtitle, a URI hostname or the notes.
func SearchCiphers(cs []*Cipher, query string) []*Cipher {
	terms := strings.Fields(fold(strings.TrimSpace(query)))
	var out []*Cipher
	for _, c := range cs {
		if !slices.ContainsFunc(terms, func(term string) bool { return !c.matchesTerm(term) }) {
			out = append(out, c)
		}
	}
	return out
}

// fold lowercases and strips diacritics for searching.
func fold(s string) string { return stripMarks(strings.ToLower(s)) }

func (c *Cipher) matchesTerm(term string) bool {
	has := func(s *string) bool { return s != nil && strings.Contains(fold(*s), term) }
	if strings.Contains(fold(c.Name), term) || (len(term) >= 8 && strings.HasPrefix(c.ID, term)) ||
		has(c.Subtitle()) || has(c.Notes) {
		return true
	}
	if c.Login == nil {
		return false
	}
	return slices.ContainsFunc(c.Login.URIs, func(u LoginURI) bool {
		if u.URI == nil {
			return false
		}
		h := Hostname(*u.URI)
		return h != "" && strings.Contains(fold(h), term)
	})
}

// SearchByName filters by case-insensitive name substring (folders, collections, orgs).
func SearchByName[T any](items []T, search string, name func(T) string) []T {
	search = strings.ToLower(search)
	var out []T
	for _, it := range items {
		if strings.Contains(strings.ToLower(name(it)), search) {
			out = append(out, it)
		}
	}
	return out
}

// URI match strategies.
const (
	MatchDomain     = 0
	MatchHost       = 1
	MatchStartsWith = 2
	MatchExact      = 3
	MatchRegex      = 4
	MatchNever      = 5
)

// domainMatchBlacklist mirrors Utils.DomainMatchBlacklist.
var domainMatchBlacklist = map[string][]string{"google.com": {"script.google.com"}}

// MatchesURL mirrors LoginUriView.matchesUri for any of the cipher's URIs.
// equivalent holds domains treated like the target's own domain (may be nil).
func (c *Cipher) MatchesURL(target string, equivalent map[string]bool, defaultMatch int) bool {
	if c.Login == nil || target == "" {
		return false
	}
	targetDomain := Domain(target)
	for _, u := range c.Login.URIs {
		if u.URI == nil || *u.URI == "" {
			continue
		}
		uri := *u.URI
		match := defaultMatch
		if u.Match != nil {
			match = *u.Match
		}
		switch match {
		case MatchDomain:
			d := Domain(uri)
			if d == "" || (d != targetDomain && !equivalent[d]) {
				continue
			}
			if bl, ok := domainMatchBlacklist[d]; ok && slices.Contains(bl, Host(target)) {
				continue
			}
			return true
		case MatchHost:
			if h := Host(target); h != "" && h == Host(uri) {
				return true
			}
		case MatchExact:
			if target == uri {
				return true
			}
		case MatchStartsWith:
			if strings.HasPrefix(target, uri) {
				return true
			}
		case MatchRegex:
			if re, err := regexp.Compile("(?i)" + uri); err == nil && re.MatchString(target) {
				return true
			}
		}
	}
	return false
}
