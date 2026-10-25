package importer

import (
	"encoding/xml"
	"regexp"
	"strings"
)

// --- keepassxcsv ---

type keepassxCSV struct{ base }

func (b *keepassxCSV) Parse(data string) (*Result, error) {
	r := &Result{}
	rows, _ := parseCSV(data, true)
	if rows == nil {
		return r, nil
	}
	for _, v := range rows {
		if v.val("Title") == nil {
			continue
		}
		group, _ := v.get("Group")
		if !ws(group) && strings.HasPrefix(group, "Root/") {
			group = strings.Replace(group, "Root/", "", 1)
		}
		if !ws(group) {
			processFolder(r, &group, true)
		}
		c := initLogin()
		c.Notes = v.val("Notes")
		c.Name = *v.val("Title")
		c.Login.Username = v.val("Username")
		c.Login.Password = v.val("Password")
		if u, ok := v.get("URL"); ok {
			c.Login.URIs = makeURIs(u)
		}
		c.Login.Totp = v.val("TOTP")
		cleanup(c)
		r.Ciphers = append(r.Ciphers, c)
	}
	if b.organization() {
		moveFoldersToCollections(r)
	}
	r.Success = true
	return r, nil
}

// --- keepass2xml ---

// node is a minimal DOM element.
type node struct {
	Name     string
	Attrs    map[string]string
	Children []*node
	text     strings.Builder
}

// textContent returns the concatenated text of the element and descendants.
func (n *node) textContent() string {
	var sb strings.Builder
	sb.WriteString(n.text.String())
	for _, c := range n.Children {
		sb.WriteString(c.textContent())
	}
	return sb.String()
}

func (n *node) children(name string) []*node {
	var out []*node
	for _, c := range n.Children {
		if c.Name == name {
			out = append(out, c)
		}
	}
	return out
}

func (n *node) child(name string) *node {
	if cs := n.children(name); len(cs) > 0 {
		return cs[0]
	}
	return nil
}

// find returns the first descendant with name (querySelector).
func (n *node) find(name string) *node {
	for _, c := range n.Children {
		if c.Name == name {
			return c
		}
		if f := c.find(name); f != nil {
			return f
		}
	}
	return nil
}

var (
	entityRe  = regexp.MustCompile(`(?i)<!ENTITY`)
	doctypeRe = regexp.MustCompile(`(?i)<!DOCTYPE[^>\[]*`)
	extIDRe   = regexp.MustCompile(`(?i)\b(?:SYSTEM|PUBLIC)\b`)
)

// parseXML builds a DOM, rejecting external entities like validateNoExternalEntities.
func parseXML(data string) *node {
	if entityRe.MatchString(data) {
		return nil
	}
	for _, d := range doctypeRe.FindAllString(data, -1) {
		if extIDRe.MatchString(d) {
			return nil
		}
	}
	dec := xml.NewDecoder(strings.NewReader(data))
	dec.Strict = false
	root := &node{}
	stack := []*node{root}
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := &node{Name: t.Name.Local, Attrs: map[string]string{}}
			for _, a := range t.Attr {
				n.Attrs[a.Name.Local] = a.Value
			}
			top := stack[len(stack)-1]
			top.Children = append(top.Children, n)
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			stack[len(stack)-1].text.Write(t)
		}
	}
	if len(stack) != 1 || len(root.Children) == 0 {
		return nil
	}
	return root
}

type keepass2XML struct {
	base
	r *Result
}

func (b *keepass2XML) Parse(data string) (*Result, error) {
	b.r = &Result{}
	doc := parseXML(data)
	if doc == nil {
		return b.r, nil
	}
	kp := doc.find("KeePassFile")
	if kp == nil {
		b.r.ErrorMessage = "Missing `KeePassFile` node."
		return b.r, nil
	}
	root := kp.find("Root")
	if root == nil {
		b.r.ErrorMessage = "Missing `KeePassFile > Root` node."
		return b.r, nil
	}
	group := root.find("Group")
	if group == nil {
		b.r.ErrorMessage = "Missing `KeePassFile > Root > Group` node."
		return b.r, nil
	}
	b.traverse(group, true, "")
	if b.organization() {
		moveFoldersToCollections(b.r)
	}
	b.r.Success = true
	return b.r, nil
}

func (b *keepass2XML) traverse(n *node, isRoot bool, prefix string) {
	folderIndex := len(b.r.Folders)
	groupName := prefix
	if !isRoot {
		if groupName != "" {
			groupName += "/"
		}
		if name := n.child("Name"); name != nil {
			groupName += name.textContent()
		} else {
			groupName += "-"
		}
		b.r.Folders = append(b.r.Folders, Folder{Name: groupName})
	}
	for _, entry := range n.children("Entry") {
		cipherIndex := len(b.r.Ciphers)
		c := initLogin()
		for _, s := range entry.children("String") {
			valueEl := s.child("Value")
			if valueEl == nil {
				continue
			}
			value := valueEl.textContent()
			if ws(value) {
				continue
			}
			key := ""
			if k := s.child("Key"); k != nil {
				key = k.textContent()
			}
			switch key {
			case "URL":
				c.Login.URIs = makeURIs(value)
			case "UserName":
				c.Login.Username = ptr(value)
			case "Password":
				c.Login.Password = ptr(value)
			case "otp":
				c.Login.Totp = ptr(strings.Replace(value, "key=", "", 1))
			case "Title":
				c.Name = value
			case "Notes":
				notes := *c.Notes + value + "\n"
				c.Notes = &notes
			default:
				if valueEl.Attrs["ProtectInMemory"] == "True" {
					c.Fields = append(c.Fields, fieldOf(1, key, value))
				} else {
					processKvp(c, key, ptr(value), 0)
				}
			}
		}
		cleanup(c)
		b.r.Ciphers = append(b.r.Ciphers, c)
		if !isRoot {
			b.r.FolderRelationships = append(b.r.FolderRelationships, [2]int{cipherIndex, folderIndex})
		}
	}
	for _, g := range n.children("Group") {
		b.traverse(g, false, groupName)
	}
}
