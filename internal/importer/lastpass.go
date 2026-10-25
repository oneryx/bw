package importer

import (
	"regexp"
	"strings"
	"time"

	"github.com/yangxiang/bw/internal/vault"
)

type lastpassCSV struct{ base }

var controlChars = regexp.MustCompile(`[\x00-\x1F\x7F-\x9F]`)

func fieldOf(t int, name, value string) vault.Field {
	return vault.Field{Type: t, Name: ptr(name), Value: ptr(value)}
}

func (b *lastpassCSV) Parse(data string) (*Result, error) {
	r := &Result{}
	rows, _ := parseCSV(data, true)
	if rows == nil {
		return r, nil
	}
	for _, v := range rows {
		cipherIndex := len(r.Ciphers)
		folderIndex := len(r.Folders)
		grouping, hasGrouping := v.get("grouping")
		if hasGrouping {
			grouping = controlChars.ReplaceAllString(strings.ReplaceAll(grouping, `\`, "/"), "")
		}
		hasFolder := hasGrouping && !ws(grouping) && grouping != "(none)"
		addFolder := hasFolder
		if hasFolder {
			for i, f := range r.Folders {
				if f.Name == grouping {
					addFolder, folderIndex = false, i
					break
				}
			}
		}
		c := b.baseCipher(v)
		switch c.Type {
		case vault.TypeLogin:
			c.Notes = v.val("extra")
			c.Login = &vault.Login{Username: v.val("username"), Password: v.val("password"), Totp: v.val("totp")}
			if u, ok := v.get("url"); ok {
				c.Login.URIs = makeURIs(u)
			}
		case vault.TypeSecureNote:
			b.parseSecureNote(v, c)
		case vault.TypeCard:
			c.Card = parseLPCard(v)
			c.Notes = v.val("notes")
		case vault.TypeIdentity:
			c.Identity = parseLPIdentity(v)
			c.Notes = v.val("notes")
			if v.val("ccnum") != nil {
				card := b.baseCipher(v)
				card.Type = vault.TypeCard
				card.Card = parseLPCard(v)
				r.Ciphers = append(r.Ciphers, card)
			}
		}
		r.Ciphers = append(r.Ciphers, c)
		if addFolder {
			r.Folders = append(r.Folders, Folder{Name: grouping})
		}
		if hasFolder {
			r.FolderRelationships = append(r.FolderRelationships, [2]int{cipherIndex, folderIndex})
		}
	}
	if b.organization() {
		moveFoldersToCollections(r)
	}
	r.Success = true
	return r, nil
}

func (b *lastpassCSV) baseCipher(v Row) *vault.Cipher {
	c := &vault.Cipher{}
	_, hasProfile := v["profilename"]
	_, hasLang := v["profilelanguage"]
	if hasProfile && hasLang {
		c.Name = "--"
		if n := v.val("profilename"); n != nil {
			c.Name = *n
		}
		c.Type = vault.TypeCard
		for _, k := range []string{"title", "firstname", "lastname", "address1", "phone", "username", "email"} {
			if v.val(k) != nil {
				c.Type = vault.TypeIdentity
				break
			}
		}
		return c
	}
	if fav := v.val("fav"); !b.organization() && fav != nil && *fav == "1" {
		c.Favorite = true
	}
	c.Name = "--"
	if n := v.val("name"); n != nil {
		c.Name = *n
	}
	if u, _ := v.get("url"); u == "http://sn" {
		c.Type = vault.TypeSecureNote
	} else {
		c.Type = vault.TypeLogin
	}
	return c
}

func parseLPCard(v Row) *vault.Card {
	card := &vault.Card{CardholderName: v.val("ccname"), Number: v.val("ccnum"), Code: v.val("cccsc")}
	card.Brand = cardBrand(card.Number)
	if exp := v.val("ccexp"); exp != nil && strings.Contains(*exp, "-") {
		parts := strings.Split(*exp, "-")
		card.ExpYear = ptr(parts[0])
		month := parts[1]
		if len(month) == 2 && month[0] == '0' {
			month = month[1:]
		}
		card.ExpMonth = ptr(month)
	}
	return card
}

func parseLPIdentity(v Row) *vault.Identity {
	id := &vault.Identity{
		Title: v.val("title"), FirstName: v.val("firstname"), MiddleName: v.val("middlename"),
		LastName: v.val("lastname"), Username: v.val("username"), Company: v.val("company"),
		SSN: v.val("ssn"), Address1: v.val("address1"), Address2: v.val("address2"),
		Address3: v.val("address3"), City: v.val("city"), State: v.val("state"),
		PostalCode: v.val("zip"), Country: v.val("country"), Email: v.val("email"), Phone: v.val("phone"),
	}
	if id.Title != nil {
		t := strings.ToUpper((*id.Title)[:1]) + (*id.Title)[1:]
		id.Title = &t
	}
	return id
}

// monthNumber mirrors getMonthNumberFromName (English month names).
func monthNumber(name string) string {
	t, err := time.Parse("January 2 2006", strings.TrimSpace(name)+" 1 2012")
	if err != nil {
		if t, err = time.Parse("Jan 2 2006", strings.TrimSpace(name)+" 1 2012"); err != nil {
			return ""
		}
	}
	return itoa(int(t.Month()))
}

func itoa(i int) string { return vault.Itoa(i) }

func (b *lastpassCSV) parseSecureNote(v Row, c *vault.Cipher) {
	extra, _ := v.get("extra")
	parts := splitNewLine(extra)
	processed := false
	if len(parts) > 0 {
		typeParts := strings.Split(parts[0], ":")
		if len(typeParts) > 1 && typeParts[0] == "NoteType" && (typeParts[1] == "Credit Card" || typeParts[1] == "Address") {
			if typeParts[1] == "Credit Card" {
				m := mapNote(c, parts, map[string]string{"Number": "number", "Name on Card": "cardholderName",
					"Security Code": "code", "Expiration Date": "expMonth"})
				card := &vault.Card{Number: m["number"], CardholderName: m["cardholderName"], Code: m["code"]}
				if exp := m["expMonth"]; exp != nil && !ws(*exp) && *exp != "," {
					monthStr, year, _ := strings.Cut(*exp, ",")
					if !ws(monthStr) {
						if mn := monthNumber(monthStr); mn != "" {
							card.ExpMonth = ptr(mn)
						}
					}
					if !ws(year) {
						card.ExpYear = ptr(year)
					}
				}
				c.Type = vault.TypeCard
				c.Card = card
			} else {
				m := mapNote(c, parts, map[string]string{"Title": "title", "First Name": "firstName",
					"Last Name": "lastName", "Middle Name": "middleName", "Company": "company",
					"Address 1": "address1", "Address 2": "address2", "Address 3": "address3",
					"City / Town": "city", "State": "state", "Zip / Postal Code": "postalCode",
					"Country": "country", "Email Address": "email", "Username": "username"})
				c.Type = vault.TypeIdentity
				c.Identity = &vault.Identity{Title: m["title"], FirstName: m["firstName"], LastName: m["lastName"],
					MiddleName: m["middleName"], Company: m["company"], Address1: m["address1"],
					Address2: m["address2"], Address3: m["address3"], City: m["city"], State: m["state"],
					PostalCode: m["postalCode"], Country: m["country"], Email: m["email"], Username: m["username"]}
			}
			processed = true
		}
	}
	if !processed {
		c.SecureNote = &vault.SecureNote{}
		c.Notes = v.val("extra")
	}
}

// mapNote mirrors parseSecureNoteMapping.
func mapNote(c *vault.Cipher, parts []string, mapping map[string]string) map[string]*string {
	out := map[string]*string{}
	processingNotes := false
	for _, part := range parts {
		if processingNotes {
			n := *c.Notes + "\n" + part
			c.Notes = &n
			continue
		}
		if ws(part) {
			continue
		}
		key, val, found := strings.Cut(part, ":")
		if !found || ws(key) || ws(val) || key == "NoteType" {
			continue
		}
		switch {
		case key == "Notes":
			if !isNullOrWhitespace(c.Notes) {
				n := *c.Notes + "\n" + val
				c.Notes = &n
			} else {
				c.Notes = ptr(val)
			}
			processingNotes = true
		case mapping[key] != "":
			out[mapping[key]] = ptr(val)
		default:
			processKvp(c, key, ptr(val), 0)
		}
	}
	return out
}
