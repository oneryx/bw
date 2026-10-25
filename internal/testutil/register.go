// Package testutil contains helpers for integration tests against a live
// Vaultwarden server.
package testutil

import (
	"encoding/base64"
	"net/http"

	"github.com/yangxiang/bw/internal/api"
	"github.com/yangxiang/bw/internal/crypto"
	"github.com/yangxiang/bw/internal/state"
)

// Register creates an account with PBKDF2 (600k iterations) like a fresh web vault signup.
func Register(serverURL, email, password string) error {
	kdf := crypto.KDFParams{Type: crypto.KDFPBKDF2, Iterations: 600000}
	mk, err := crypto.MasterKey(password, email, kdf)
	if err != nil {
		return err
	}
	userKey := crypto.GenerateSymmetricKey()
	protected, err := crypto.Encrypt(crypto.StretchKey(mk), userKey.Bytes())
	if err != nil {
		return err
	}
	pub, priv, err := crypto.GenerateKeyPair()
	if err != nil {
		return err
	}
	encPriv, err := crypto.Encrypt(userKey, priv)
	if err != nil {
		return err
	}
	c := &api.Client{Env: state.Environment{Base: serverURL}}
	// Without SMTP, Vaultwarden returns the verification token directly.
	var token string
	if err := c.SendIdentity(http.MethodPost, "/accounts/register/send-verification-email",
		map[string]any{"email": email, "name": "Test User", "receiveMarketingEmails": false}, &token); err != nil {
		return err
	}
	body := map[string]any{
		"email":                  email,
		"emailVerificationToken": token,
		"masterPasswordHash":     crypto.MasterPasswordHash(mk, password),
		"masterPasswordHint":     nil,
		"userSymmetricKey":       protected.String(),
		"userAsymmetricKeys": map[string]string{
			"publicKey":           base64.StdEncoding.EncodeToString(pub),
			"encryptedPrivateKey": encPriv.String(),
		},
		"kdf":           kdf.Type,
		"kdfIterations": kdf.Iterations,
	}
	return c.SendIdentity(http.MethodPost, "/accounts/register/finish", body, nil)
}
