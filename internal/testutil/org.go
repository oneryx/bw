package testutil

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/oneryx/bw/internal/api"
	"github.com/oneryx/bw/internal/crypto"
	"github.com/oneryx/bw/internal/state"
	"github.com/oneryx/bw/totp"
)

// Session is a logged-in test user.
type Session struct {
	Client  *api.Client
	UserKey *crypto.SymmetricKey
	Profile struct {
		ID         string `json:"id"`
		PrivateKey string `json:"privateKey"`
	}
}

// Login performs a password login and fetches the profile.
func Login(serverURL, email, password string) (*Session, error) {
	c := &api.Client{Env: state.Environment{Base: serverURL}, DeviceID: "11111111-2222-3333-4444-555555555555", Tokens: &state.Tokens{}}
	pre, err := c.Prelogin(context.Background(), email)
	if err != nil {
		return nil, err
	}
	kdf := crypto.KDFParams{Type: pre.Kdf, Iterations: pre.KdfIterations}
	if pre.KdfMemory != nil {
		kdf.Memory = *pre.KdfMemory
	}
	if pre.KdfParallelism != nil {
		kdf.Parallelism = *pre.KdfParallelism
	}
	mk, err := crypto.MasterKey(password, email, kdf)
	if err != nil {
		return nil, err
	}
	form := url.Values{"grant_type": {"password"}, "scope": {"api offline_access"}, "client_id": {"cli"},
		"username": {strings.ToLower(email)}, "password": {crypto.MasterPasswordHash(mk, password)}}
	tr, err := c.Token(context.Background(), form)
	if err != nil {
		return nil, err
	}
	api.SetTokens(c.Tokens, tr)
	uk, err := crypto.DecryptUserKey(mk, tr.Key)
	if err != nil {
		return nil, err
	}
	s := &Session{Client: c, UserKey: uk}
	return s, c.Get(context.Background(), "/accounts/profile", &s.Profile)
}

// CreateOrg creates an organization owned by the session user and returns its id.
func (s *Session) CreateOrg(name, collectionName string) (string, error) {
	privDER, err := crypto.DecryptBytes(s.UserKey, s.Profile.PrivateKey)
	if err != nil {
		return "", err
	}
	priv, err := crypto.ParsePrivateKey(privDER)
	if err != nil {
		return "", err
	}
	pub, err := crypto.PublicKeyDER(priv)
	if err != nil {
		return "", err
	}
	orgKey := crypto.GenerateSymmetricKey()
	wrapped, err := crypto.EncryptRSA(pub, orgKey.Bytes())
	if err != nil {
		return "", err
	}
	orgPub, orgPriv, err := crypto.GenerateKeyPair()
	if err != nil {
		return "", err
	}
	encOrgPriv, err := crypto.Encrypt(orgKey, orgPriv)
	if err != nil {
		return "", err
	}
	coll, err := crypto.EncryptString(orgKey, collectionName)
	if err != nil {
		return "", err
	}
	body := map[string]any{
		"name": name, "billingEmail": "billing@example.com", "collectionName": coll,
		"key": wrapped, "planType": 0,
		"keys": map[string]string{"publicKey": base64.StdEncoding.EncodeToString(orgPub), "encryptedPrivateKey": encOrgPriv.String()},
	}
	var res struct {
		ID string `json:"id"`
	}
	if err := s.Client.Do(context.Background(), http.MethodPost, "/organizations", body, &res); err != nil {
		return "", err
	}
	if res.ID == "" {
		return "", errors.New("no organization id returned")
	}
	return res.ID, nil
}

// Invite invites an email as a regular user and returns the member id.
func (s *Session) Invite(orgID, email string) (string, error) {
	body := map[string]any{"emails": []string{email}, "type": 2, "collections": []any{}, "accessAll": false, "groups": []any{}, "permissions": map[string]any{}}
	if err := s.Client.Do(context.Background(), http.MethodPost, "/organizations/"+orgID+"/users/invite", body, nil); err != nil {
		return "", err
	}
	var users struct {
		Data []struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"data"`
	}
	if err := s.Client.Get(context.Background(), "/organizations/"+orgID+"/users", &users); err != nil {
		return "", err
	}
	for _, u := range users.Data {
		if strings.EqualFold(u.Email, email) {
			return u.ID, nil
		}
	}
	return "", errors.New("invited member not found")
}

// EnableTOTP turns on authenticator 2FA and returns the base32 secret.
func (s *Session) EnableTOTP(email, password string) (string, error) {
	pre, err := s.Client.Prelogin(context.Background(), email)
	if err != nil {
		return "", err
	}
	kdf := crypto.KDFParams{Type: pre.Kdf, Iterations: pre.KdfIterations}
	mk, err := crypto.MasterKey(password, email, kdf)
	if err != nil {
		return "", err
	}
	hash := crypto.MasterPasswordHash(mk, password)
	var res struct {
		Key string `json:"key"`
	}
	if err := s.Client.Do(context.Background(), http.MethodPost, "/two-factor/get-authenticator", map[string]string{"masterPasswordHash": hash}, &res); err != nil {
		return "", err
	}
	code, err := totp.Generate(res.Key)
	if err != nil {
		return "", err
	}
	body := map[string]string{"key": res.Key, "token": code, "masterPasswordHash": hash}
	return res.Key, s.Client.Do(context.Background(), http.MethodPost, "/two-factor/authenticator", body, nil)
}

// AddAttachment encrypts and uploads a file to a personal item without a
// per-item key (as created by import).
func (s *Session) AddAttachment(itemID, fileName string, data []byte) error {
	ctx := context.Background()
	attKey := crypto.GenerateSymmetricKey()
	encKey, err := crypto.Encrypt(s.UserKey, attKey.Bytes())
	if err != nil {
		return err
	}
	encName, err := crypto.EncryptString(s.UserKey, fileName)
	if err != nil {
		return err
	}
	encData, err := crypto.EncryptBuffer(attKey, data)
	if err != nil {
		return err
	}
	var up struct {
		AttachmentID string `json:"attachmentId"`
	}
	body := map[string]any{"key": encKey.String(), "fileName": encName, "fileSize": len(encData), "adminRequest": false}
	if err := s.Client.Do(ctx, http.MethodPost, "/ciphers/"+itemID+"/attachment/v2", body, &up); err != nil {
		return err
	}
	return postFile(ctx, s.Client.Env.APIURL()+"/ciphers/"+itemID+"/attachment/"+up.AttachmentID,
		s.Client.Tokens.AccessToken, "data", encName, encData)
}

// Seed creates test data in the personal vault: folder "Work" holding the
// login "GitHub" (alice / pw2, TOTP, URI, history pw1), and the items "Doc"
// (secure note "secret note") and "Card" without a folder.
func (s *Session) Seed() error {
	ctx := context.Background()
	var encErr error
	enc := func(v string) string {
		e, err := crypto.EncryptString(s.UserKey, v)
		if err != nil {
			encErr = err
		}
		return e
	}
	var folder struct {
		ID string `json:"id"`
	}
	if err := s.Client.Do(ctx, http.MethodPost, "/folders", map[string]string{"name": enc("Work")}, &folder); err != nil {
		return err
	}
	items := []map[string]any{
		{"type": 1, "name": enc("GitHub"), "notes": enc("n"), "folderId": folder.ID,
			"login": map[string]any{"username": enc("alice"), "password": enc("pw2"), "totp": enc("JBSWY3DPEHPK3PXP"),
				"uris": []map[string]any{{"uri": enc("https://github.com/login"), "match": nil}}},
			"passwordHistory": []map[string]string{{"password": enc("pw1"), "lastUsedDate": "2026-01-01T00:00:00.000Z"}}},
		{"type": 2, "name": enc("Doc"), "notes": enc("secret note"), "secureNote": map[string]int{"type": 0}},
		{"type": 3, "name": enc("Card"), "card": map[string]any{"number": enc("4111111111111111")}},
	}
	if encErr != nil {
		return encErr
	}
	for _, it := range items {
		it["favorite"], it["reprompt"], it["fields"] = false, 0, []any{}
		// Vaultwarden rejects the cipher (422) without these.
		it["organizationId"], it["key"], it["encryptedFor"] = nil, nil, s.Profile.ID
		if err := s.Client.Do(ctx, http.MethodPost, "/ciphers", it, nil); err != nil {
			return err
		}
	}
	return nil
}
