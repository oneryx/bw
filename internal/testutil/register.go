// Package testutil contains helpers for integration tests against a live
// Vaultwarden server.
package testutil

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/oneryx/bw/internal/crypto"
	"github.com/oneryx/bw/internal/state"
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
	ctx := context.Background()
	identity := state.Environment{Base: serverURL}.IdentityURL()
	// Without SMTP, Vaultwarden returns the verification token directly.
	resp, err := postJSON(ctx, identity+"/accounts/register/send-verification-email",
		map[string]any{"email": email, "name": "Test User", "receiveMarketingEmails": false})
	if err != nil {
		return err
	}
	var token string
	if json.Unmarshal(resp, &token) != nil {
		token = string(resp)
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
	_, err = postJSON(ctx, identity+"/accounts/register/finish", body)
	return err
}
