// Package importer ports the official vault importers for the formats this
// CLI supports. Importers produce decrypted ciphers plus folder/collection
// relationships, which the CLI encrypts and posts to the server.
package importer

import (
	"encoding/csv"
	"errors"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/yangxiang/bw/internal/vault"
)

// Folder is an imported folder (ID set when importing a Bitwarden export).
type Folder struct {
	ID   *string
	Name string
}

// Collection is an imported collection.
type Collection struct {
	ID         *string
	Name       string
	ExternalID *string
}

// Result mirrors ImportResult.
type Result struct {
	Success                 bool
	ErrorMessage            string
	Ciphers                 []*vault.Cipher
	Folders                 []Folder
	FolderRelationships     [][2]int
	Collections             []Collection
	CollectionRelationships [][2]int
}

// Options carries the context an importer may need.
type Options struct {
	// OrganizationID is set for organization imports.
	OrganizationID string
	// Vault gives access to keys for encrypted Bitwarden exports.
	Vault *vault.Vault
	// Password returns the file password for password-protected exports.
	Password func() (string, error)
}

// Importer parses file contents.
type Importer interface {
	Parse(data string) (*Result, error)
}

type factory func(o Options) Importer

var registry = map[string]factory{
	"bitwardencsv":  func(o Options) Importer { return &bitwardenCSV{base{o}} },
	"bitwardenjson": func(o Options) Importer { return &bitwardenJSON{base{o}} },
	"chromecsv":     func(o Options) Importer { return &chromeCSV{base{o}} },
	"bravecsv":      func(o Options) Importer { return &chromeCSV{base{o}} },
	"edgecsv":       func(o Options) Importer { return &chromeCSV{base{o}} },
	"operacsv":      func(o Options) Importer { return &chromeCSV{base{o}} },
	"vivaldicsv":    func(o Options) Importer { return &chromeCSV{base{o}} },
	"firefoxcsv":    func(o Options) Importer { return &firefoxCSV{base{o}} },
	"keepass2xml":   func(o Options) Importer { return &keepass2XML{base: base{o}} },
	"keepassxcsv":   func(o Options) Importer { return &keepassxCSV{base{o}} },
	"lastpasscsv":   func(o Options) Importer { return &lastpassCSV{base{o}} },
}

// Formats returns the supported format ids, sorted.
func Formats() []string {
	var out []string
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Get returns the importer for a format, or nil.
func Get(format string, o Options) Importer {
	f, ok := registry[format]
	if !ok {
		return nil
	}
	return f(o)
}

// OfficialFormats lists every format id the official CLI accepts, so known
// but unsupported formats get a clear message.
var OfficialFormats = []string{
	"1password1pif", "1password1pux", "1passwordmaccsv", "1passwordwincsv", "arccsv", "ascendocsv",
	"avastcsv", "avastjson", "aviracsv", "bitwardencsv", "bitwardenjson", "blackberrycsv", "blurcsv",
	"bravecsv", "buttercupcsv", "chromecsv", "clipperzhtml", "codebookcsv", "dashlanecsv",
	"dashlanejson", "delineacsv", "delineaxml", "edgecsv", "encryptrcsv", "enpasscsv", "enpassjson",
	"firefoxcsv", "fsecurefsk", "gnomejson", "kasperskytxt", "keepass2xml", "keepasskdbx",
	"keepassxcsv", "keeper", "keepercsv", "keeperjson", "lastpasscsv", "logmeoncecsv", "meldiumcsv",
	"msecurecsv", "mykicsv", "netwrixpasswordsecure", "nordpasscsv", "operacsv", "padlockcsv",
	"passboltcsv", "passkeepcsv", "passkyjson", "passmanjson", "passpackcsv", "passwordagentcsv",
	"passwordbossjson", "passworddepot17xml", "passworddragonxml", "passwordwallettxt",
	"passwordxpcsv", "protonpass", "psonojson", "pwsafexml", "remembearcsv", "roboformcsv",
	"safaricsv", "safeincloudxml", "saferpasscsv", "securesafecsv", "splashidcsv",
	"stickypasswordxml", "truekeycsv", "upmcsv", "vivaldicsv", "yoticsv", "zohovaultcsv",
}

// ErrFormat is the official importFormatError message.
var ErrFormat = errors.New("Data is not formatted correctly. Please check your import file and try again.")

// --- base helpers (BaseImporter) ---

type base struct{ opts Options }

func (b base) organization() bool { return b.opts.OrganizationID != "" }

var newLineRe = regexp.MustCompile(`\r\n|\r|\n`)

func isNullOrWhitespace(s *string) bool { return s == nil || strings.TrimSpace(*s) == "" }

func ws(s string) bool { return strings.TrimSpace(s) == "" }

func ptr(s string) *string { return &s }

// valueOrDefault mirrors getValueOrDefault.
func valueOrDefault(s string, ok bool, def *string) *string {
	if !ok || ws(s) {
		return def
	}
	return &s
}

func splitNewLine(s string) []string { return newLineRe.Split(s, -1) }

// Row is a parsed CSV record keyed by header.
type Row map[string]string

func (r Row) get(k string) (string, bool) {
	v, ok := r[k]
	return v, ok
}

// val returns getValueOrDefault(row[k]).
func (r Row) val(k string) *string {
	v, ok := r[k]
	return valueOrDefault(v, ok, nil)
}

// parseCSV mirrors parseCsv with papaparse's lenient defaults.
func parseCSV(data string, header bool) ([]Row, [][]string) {
	data = strings.TrimPrefix(data, "\uFEFF")
	data = strings.TrimSpace(strings.Join(splitNewLine(data), "\n"))
	if data == "" {
		return nil, nil
	}
	rd := csv.NewReader(strings.NewReader(data))
	rd.LazyQuotes = true
	rd.FieldsPerRecord = -1
	records, err := rd.ReadAll()
	if err != nil && len(records) == 0 {
		return nil, nil
	}
	if !header {
		return nil, records
	}
	if len(records) < 2 {
		return nil, nil
	}
	head := records[0]
	var rows []Row
	for _, rec := range records[1:] {
		row := Row{}
		for i, h := range head {
			if i < len(rec) {
				row[h] = rec[i]
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// parseSingleRowCSV mirrors parseSingleRowCsv.
func parseSingleRowCSV(s *string) []string {
	if isNullOrWhitespace(s) {
		return nil
	}
	_, recs := parseCSV(*s, false)
	if len(recs) > 0 && len(recs[0]) > 0 {
		return recs[0]
	}
	return nil
}

func fixURI(u string) string {
	u = strings.TrimSpace(u)
	if !strings.Contains(u, "://") && strings.Contains(u, ".") {
		u = "http://" + u
	}
	if len(u) > 1000 {
		u = u[:1000]
	}
	return u
}

// makeURIs mirrors makeUriArray.
func makeURIs(uris ...string) []vault.LoginURI {
	var out []vault.LoginURI
	for _, u := range uris {
		f := fixURI(u)
		if ws(f) {
			continue
		}
		out = append(out, vault.LoginURI{URI: ptr(f)})
	}
	return out
}

func makeURIsPtr(u *string) []vault.LoginURI {
	if u == nil {
		return nil
	}
	return makeURIs(*u)
}

func nameFromURL(u *string) *string {
	if u == nil {
		return nil
	}
	h := vault.Hostname(*u)
	if ws(h) {
		return nil
	}
	h = strings.Replace(h, "www.", "", 1)
	return &h
}

func initLogin() *vault.Cipher {
	empty := ""
	return &vault.Cipher{Type: vault.TypeLogin, Notes: &empty, Fields: []vault.Field{}, Login: &vault.Login{}}
}

// cleanup mirrors cleanupCipher.
func cleanup(c *vault.Cipher) {
	if c.Type != vault.TypeLogin {
		c.Login = nil
	}
	if ws(c.Name) {
		c.Name = "--"
	}
	if isNullOrWhitespace(c.Notes) {
		c.Notes = nil
	}
}

// processKvp mirrors processKvp: long or multi-line values go to notes.
func processKvp(c *vault.Cipher, key string, value *string, fieldType int) {
	if isNullOrWhitespace(value) {
		return
	}
	v := *value
	if len([]rune(v)) > 200 || newLineRe.MatchString(strings.TrimSpace(v)) {
		notes := ""
		if c.Notes != nil {
			notes = *c.Notes
		}
		notes += key + ": " + strings.Join(splitNewLine(v), "\n") + "\n"
		c.Notes = &notes
		return
	}
	c.Fields = append(c.Fields, vault.Field{Type: fieldType, Name: ptr(key), Value: ptr(v)})
}

// processFolder mirrors processFolder (with implicit parent folders).
func processFolder(r *Result, name *string, addRelationship bool) {
	if isNullOrWhitespace(name) {
		return
	}
	folderName := strings.ReplaceAll(*name, `\`, "/")
	folderName = strings.TrimLeft(folderName, "/")
	idx := len(r.Folders)
	found := false
	for i, f := range r.Folders {
		if f.Name == folderName {
			idx, found = i, true
			break
		}
	}
	if !found {
		r.Folders = append(r.Folders, Folder{Name: folderName})
	}
	if addRelationship {
		r.FolderRelationships = append(r.FolderRelationships, [2]int{len(r.Ciphers), idx})
	}
	parts := strings.Split(folderName, "/")
	for i := len(parts) - 1; i > 0; i-- {
		parent := strings.Join(parts[:i], "/")
		if !slices.ContainsFunc(r.Folders, func(f Folder) bool { return f.Name == parent }) {
			r.Folders = append(r.Folders, Folder{Name: parent})
		}
	}
}

// moveFoldersToCollections mirrors the organization import conversion.
func moveFoldersToCollections(r *Result) {
	r.CollectionRelationships = append(r.CollectionRelationships, r.FolderRelationships...)
	for _, f := range r.Folders {
		r.Collections = append(r.Collections, Collection{ID: f.ID, Name: f.Name})
	}
	r.FolderRelationships = nil
	r.Folders = nil
}

// cardBrand mirrors CardView.getCardBrandByPatterns.
func cardBrand(num *string) *string {
	if isNullOrWhitespace(num) {
		return nil
	}
	n := *num
	m := func(re string) bool { return regexp.MustCompile(re).MatchString(n) }
	switch {
	case m(`^4`):
		return ptr("Visa")
	case m(`^(5[1-5][0-9]{14}|2(22[1-9][0-9]{12}|2[3-9][0-9]{13}|[3-6][0-9]{14}|7[0-1][0-9]{13}|720[0-9]{12}))$`):
		return ptr("Mastercard")
	case m(`^3[47]`):
		return ptr("Amex")
	case m(`^(6011|622(12[6-9]|1[3-9][0-9]|[2-8][0-9]{2}|9[0-1][0-9]|92[0-5]|64[4-9])|65)`):
		return ptr("Discover")
	case m(`^36`), m(`^30[0-5]`):
		return ptr("Diners Club")
	case m(`^35(2[89]|[3-8][0-9])`):
		return ptr("JCB")
	}
	return nil
}
