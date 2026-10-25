package importer

import (
	"strings"
)

// --- chromecsv (also Brave, Edge, Opera, Vivaldi) ---

type chromeCSV struct{ base }

func androidPackage(url string) (string, bool) {
	if !strings.HasPrefix(url, "android://") {
		return "", false
	}
	at := strings.Index(url, "@")
	if at == -1 {
		return "", false
	}
	rest := url[at+1:]
	if slash := strings.Index(rest, "/"); slash != -1 {
		rest = rest[:slash]
	}
	return rest, true
}

func (b *chromeCSV) Parse(data string) (*Result, error) {
	r := &Result{}
	rows, _ := parseCSV(data, true)
	if rows == nil {
		return r, nil
	}
	for _, v := range rows {
		c := initLogin()
		url, hasURL := v.get("url")
		normalized := url
		if pkg, ok := androidPackage(url); ok {
			normalized = "androidapp://" + pkg
		}
		name, _ := v.get("name")
		if name == "" {
			if pkg, ok := androidPackage(url); ok {
				name = pkg
			}
		}
		c.Name = "--"
		if n := valueOrDefault(name, true, nil); n != nil {
			c.Name = *n
		}
		c.Login.Username = v.val("username")
		c.Login.Password = v.val("password")
		if hasURL {
			c.Login.URIs = makeURIs(normalized)
		}
		c.Notes = v.val("note")
		cleanup(c)
		r.Ciphers = append(r.Ciphers, c)
	}
	r.Success = true
	return r, nil
}

// --- firefoxcsv ---

type firefoxCSV struct{ base }

func (b *firefoxCSV) Parse(data string) (*Result, error) {
	r := &Result{}
	rows, _ := parseCSV(data, true)
	if rows == nil {
		return r, nil
	}
	for _, v := range rows {
		if u, _ := v.get("url"); u == "chrome://FirefoxAccounts" {
			continue
		}
		c := initLogin()
		url := v.val("url")
		if url == nil {
			url = v.val("hostname")
		}
		c.Name = "--"
		if n := nameFromURL(url); n != nil && !ws(*n) {
			c.Name = *n
		}
		c.Login.Username = v.val("username")
		c.Login.Password = v.val("password")
		c.Login.URIs = makeURIsPtr(url)
		cleanup(c)
		r.Ciphers = append(r.Ciphers, c)
	}
	r.Success = true
	return r, nil
}
