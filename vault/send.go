package vault

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/oneryx/bw/internal/crypto"
)

// Send types and auth types.
const (
	SendTypeText = 0
	SendTypeFile = 1

	SendAuthEmail    = 0
	SendAuthPassword = 1
	SendAuthNone     = 2
)

// sendKDFIterations is SEND_KDF_ITERATIONS in the official clients.
const sendKDFIterations = 100000

// Send is the server representation of a Send (encrypted or decrypted).
type Send struct {
	ID             string    `json:"id,omitempty"`
	AccessID       string    `json:"accessId,omitempty"`
	Type           int       `json:"type"`
	Name           string    `json:"name"`
	Notes          *string   `json:"notes"`
	Key            string    `json:"key"`
	Text           *SendText `json:"text"`
	File           *SendFile `json:"file"`
	MaxAccessCount *int      `json:"maxAccessCount"`
	AccessCount    int       `json:"accessCount"`
	RevisionDate   string    `json:"revisionDate,omitempty"`
	DeletionDate   string    `json:"deletionDate"`
	ExpirationDate *string   `json:"expirationDate"`
	Password       *string   `json:"password"`
	Disabled       bool      `json:"disabled"`
	HideEmail      bool      `json:"hideEmail"`
	AuthType       *int      `json:"authType,omitempty"`
}

type SendText struct {
	Text   *string `json:"text"`
	Hidden bool    `json:"hidden"`
}

type SendFile struct {
	ID       string     `json:"id,omitempty"`
	FileName string     `json:"fileName"`
	Size     FlexString `json:"size,omitempty"`
	SizeName string     `json:"sizeName,omitempty"`
}

// DecryptedSend pairs a decrypted Send with its raw key material.
type DecryptedSend struct {
	Send
	KeyMaterial []byte
}

// SendCryptoKey derives the symmetric key from the 16-byte Send key material.
func SendCryptoKey(material []byte) *crypto.SymmetricKey {
	return crypto.ShareableKey(material, "send", "send")
}

// SendPasswordHash hashes a Send password: PBKDF2-SHA256(password, keyMaterial, 100000).
func SendPasswordHash(password string, material []byte) string {
	h, _ := pbkdf2.Key(sha256.New, password, material, sendKDFIterations, 32)
	return base64.StdEncoding.EncodeToString(h)
}

func decryptOpt(k *crypto.SymmetricKey, p *string) *string {
	if p == nil {
		return nil
	}
	s, err := crypto.DecryptString(k, *p)
	if err != nil {
		s = DecryptError
	}
	return &s
}

// DecryptSendWith decrypts a Send's fields with the given key material.
func DecryptSendWith(s Send, material []byte) *DecryptedSend {
	k := SendCryptoKey(material)
	out := s
	if out.Name != "" {
		out.Name = *decryptOpt(k, &out.Name)
	}
	out.Notes = decryptOpt(k, s.Notes)
	if s.Text != nil {
		t := *s.Text
		t.Text = decryptOpt(k, s.Text.Text)
		out.Text = &t
	}
	if s.File != nil {
		f := *s.File
		f.FileName = *decryptOpt(k, &s.File.FileName)
		out.File = &f
	}
	return &DecryptedSend{Send: out, KeyMaterial: material}
}

// Sends returns the user's decrypted Sends sorted by name.
func (v *Vault) Sends() []*DecryptedSend {
	var out []*DecryptedSend
	for _, raw := range v.Data.Sends {
		var s Send
		if json.Unmarshal(raw, &s) != nil {
			continue
		}
		material, err := crypto.DecryptBytes(v.UserKey, s.Key)
		if err != nil {
			continue
		}
		out = append(out, DecryptSendWith(s, material))
	}
	sortBy(out, func(s *DecryptedSend) string { return s.Name })
	return out
}

// EncryptSend encrypts a decrypted Send; key material is (re)wrapped with the user key.
func (v *Vault) EncryptSend(d *DecryptedSend) (*Send, error) {
	k := SendCryptoKey(d.KeyMaterial)
	out := d.Send
	wrapped, err := crypto.Encrypt(v.UserKey, d.KeyMaterial)
	if err != nil {
		return nil, err
	}
	out.Key = wrapped.String()
	enc := func(p *string) (*string, error) {
		if p == nil {
			return nil, nil
		}
		s, err := crypto.EncryptString(k, *p)
		return &s, err
	}
	name, err := enc(&d.Name)
	if err != nil {
		return nil, err
	}
	out.Name = *name
	if out.Notes, err = enc(d.Notes); err != nil {
		return nil, err
	}
	if d.Text != nil {
		t := *d.Text
		if t.Text, err = enc(d.Text.Text); err != nil {
			return nil, err
		}
		out.Text = &t
	}
	if d.File != nil {
		f := *d.File
		fn, err := enc(&d.File.FileName)
		if err != nil {
			return nil, err
		}
		f.FileName = *fn
		out.File = &f
	}
	return &out, nil
}

// SendResponse is the CLI "send" object shape.
type SendResponse struct {
	Object         string            `json:"object"`
	ID             string            `json:"id"`
	AccessID       string            `json:"accessId"`
	AccessURL      string            `json:"accessUrl"`
	Name           string            `json:"name"`
	Notes          *string           `json:"notes"`
	Key            string            `json:"key"`
	Type           int               `json:"type"`
	MaxAccessCount *int              `json:"maxAccessCount"`
	AccessCount    int               `json:"accessCount"`
	RevisionDate   string            `json:"revisionDate"`
	DeletionDate   string            `json:"deletionDate"`
	ExpirationDate *string           `json:"expirationDate"`
	PasswordSet    bool              `json:"passwordSet"`
	Emails         []string          `json:"emails"`
	Disabled       bool              `json:"disabled"`
	HideEmail      bool              `json:"hideEmail"`
	AuthType       *int              `json:"authType,omitempty"`
	Text           *SendTextResponse `json:"text,omitempty"`
	File           *SendFileResponse `json:"file,omitempty"`
}

type SendTextResponse struct {
	Text   *string `json:"text"`
	Hidden bool    `json:"hidden"`
}

type SendFileResponse struct {
	ID       string `json:"id"`
	Size     string `json:"size"`
	SizeName string `json:"sizeName"`
	FileName string `json:"fileName"`
}

// URLKey returns the base64url (unpadded) key used in access URLs.
func URLKey(material []byte) string { return base64.RawURLEncoding.EncodeToString(material) }

// SendOutput formats a decrypted Send like the official CLI.
func SendOutput(d *DecryptedSend, sendURL string) SendResponse {
	r := SendResponse{
		Object: "send", ID: d.ID, AccessID: d.AccessID,
		AccessURL: sendURL + d.AccessID + "/" + URLKey(d.KeyMaterial),
		Name:      d.Name, Notes: d.Notes, Key: base64.StdEncoding.EncodeToString(d.KeyMaterial),
		Type: d.Type, MaxAccessCount: d.MaxAccessCount, AccessCount: d.AccessCount,
		RevisionDate: JSDate(d.RevisionDate), DeletionDate: JSDate(d.DeletionDate),
		ExpirationDate: jsDatePtr(d.ExpirationDate), PasswordSet: d.Password != nil,
		Emails: []string{}, Disabled: d.Disabled, HideEmail: d.HideEmail, AuthType: d.AuthType,
	}
	if d.Type == SendTypeText && d.Text != nil {
		r.Text = &SendTextResponse{Text: d.Text.Text, Hidden: d.Text.Hidden}
	}
	if d.Type == SendTypeFile && d.File != nil {
		r.File = &SendFileResponse{ID: d.File.ID, Size: string(d.File.Size), SizeName: d.File.SizeName, FileName: d.File.FileName}
	}
	return r
}

// SendAccessResponse is the "send-access" object returned by `bw receive --obj`.
type SendAccessResponse struct {
	Object string            `json:"object"`
	ID     string            `json:"id"`
	Name   string            `json:"name"`
	Type   int               `json:"type"`
	Text   *SendTextResponse `json:"text,omitempty"`
	File   *SendFileResponse `json:"file,omitempty"`
}

// SendTemplate returns the official send template for a type.
func SendTemplate(sendType int, deletionDate string) json.RawMessage {
	text, file := "null", "null"
	if sendType == SendTypeText {
		text = `{"text":"Text contained in the send.","hidden":false}`
	} else {
		file = `{"fileName":"file attachment location"}`
	}
	return json.RawMessage(`{"object":"send","name":"Send name","notes":"Some notes about this send.","type":` +
		Itoa(sendType) + `,"text":` + text + `,"file":` + file +
		`,"maxAccessCount":null,"deletionDate":"` + deletionDate +
		`","expirationDate":null,"password":null,"emails":null,"disabled":false,"hideEmail":false}`)
}

// SearchSends mirrors SearchService.searchSends.
func SearchSends(sends []*DecryptedSend, query string) []*DecryptedSend {
	q := stripMarks(strings.ToLower(strings.TrimSpace(query)))
	var hi, lo []*DecryptedSend
	for _, s := range sends {
		lower := func(p *string) string {
			if p == nil {
				return ""
			}
			return strings.ToLower(*p)
		}
		switch {
		case strings.Contains(strings.ToLower(s.Name), q):
			hi = append(hi, s)
		case len(q) >= 8 && (strings.HasPrefix(s.ID, q) || strings.HasPrefix(strings.ToLower(s.AccessID), q) ||
			(s.File != nil && s.File.ID != "" && strings.HasPrefix(s.File.ID, q))):
			lo = append(lo, s)
		case s.Notes != nil && strings.Contains(lower(s.Notes), q):
			lo = append(lo, s)
		case s.Text != nil && s.Text.Text != nil && strings.Contains(lower(s.Text.Text), q):
			lo = append(lo, s)
		case s.File != nil && strings.Contains(strings.ToLower(s.File.FileName), q):
			lo = append(lo, s)
		}
	}
	return append(hi, lo...)
}
