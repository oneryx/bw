package bw

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/oneryx/bw/internal/api"
	"github.com/oneryx/bw/internal/crypto"
	"github.com/oneryx/bw/internal/state"
	"github.com/oneryx/bw/vault"
)

// Sends returns the user's decrypted Sends sorted by name.
func (c *Client) Sends() ([]*vault.DecryptedSend, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return nil, err
	}
	return v.Sends(), nil
}

// SendBaseURL returns the prefix of Send access URLs; append
// AccessID + "/" + vault.URLKey(KeyMaterial).
func (c *Client) SendBaseURL() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st.Environment.WebVaultURL() + "/#/send/"
}

func setSendPassword(d *vault.DecryptedSend, password string) {
	at := vault.SendAuthNone
	d.Password = nil
	if strings.TrimSpace(password) != "" {
		h := vault.SendPasswordHash(password, d.KeyMaterial)
		d.Password = &h
		at = vault.SendAuthPassword
	}
	d.AuthType = &at
}

// CreateSend creates a text Send (s.Text set) or a file Send (s.File.FileName
// set, content in fileData). Key material is generated when empty; a
// non-empty password protects the Send.
func (c *Client) CreateSend(ctx context.Context, s *vault.DecryptedSend, password string, fileData []byte) (*vault.DecryptedSend, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return nil, err
	}
	d := *s
	if len(d.KeyMaterial) == 0 {
		d.KeyMaterial = crypto.RandomBytes(16)
	}
	setSendPassword(&d, password)
	enc, err := v.EncryptSend(&d)
	if err != nil {
		return nil, err
	}
	cl := c.api()
	body := sendBody(enc)
	var raw json.RawMessage
	if enc.Type != vault.SendTypeFile {
		if err := cl.Do(ctx, http.MethodPost, "/sends", body, &raw); err != nil {
			return nil, err
		}
		return c.cacheSend(v, raw)
	}
	if enc.File == nil {
		return nil, errors.New("A file Send needs a file name.")
	}
	encFile, err := crypto.EncryptBuffer(vault.SendCryptoKey(d.KeyMaterial), fileData)
	if err != nil {
		return nil, err
	}
	body["file"] = map[string]string{"fileName": enc.File.FileName}
	body["fileLength"] = len(encFile)
	var up struct {
		FileUploadType int             `json:"fileUploadType"`
		SendResponse   json.RawMessage `json:"sendResponse"`
	}
	if err := cl.Do(ctx, http.MethodPost, "/sends/file/v2", body, &up); err != nil {
		return nil, err
	}
	var created vault.Send
	if err := json.Unmarshal(up.SendResponse, &created); err != nil {
		return nil, err
	}
	if up.FileUploadType != 0 || created.File == nil {
		return nil, errors.New("unsupported Send file upload type")
	}
	mp, err := api.Multipart(nil, "data", enc.File.FileName, encFile)
	if err != nil {
		return nil, err
	}
	if err := cl.SendRaw(ctx, http.MethodPost, cl.Env.APIURL()+"/sends/"+created.ID+"/file/"+created.File.ID, mp, nil); err != nil {
		_ = cl.Do(ctx, http.MethodDelete, "/sends/"+created.ID, nil, nil)
		return nil, err
	}
	if err := cl.Get(ctx, "/sends/"+created.ID, &raw); err != nil {
		return nil, err
	}
	return c.cacheSend(v, raw)
}

func sendBody(enc *vault.Send) map[string]any {
	return map[string]any{
		"type": enc.Type, "name": enc.Name, "notes": enc.Notes, "key": enc.Key,
		"maxAccessCount": enc.MaxAccessCount, "expirationDate": enc.ExpirationDate,
		"deletionDate": enc.DeletionDate, "text": enc.Text, "password": enc.Password,
		"disabled": enc.Disabled, "hideEmail": enc.HideEmail, "authType": enc.AuthType,
	}
}

// UpdateSend saves changes to an existing Send (matched by s.ID). A non-empty
// password replaces the current one; otherwise the current password is kept.
// The type of a Send cannot change.
func (c *Client) UpdateSend(ctx context.Context, s *vault.DecryptedSend, password string) (*vault.DecryptedSend, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return nil, err
	}
	var cur *vault.DecryptedSend
	for _, x := range v.Sends() {
		if x.ID == strings.ToLower(s.ID) {
			cur = x
		}
	}
	if cur == nil {
		return nil, ErrNotFound
	}
	if cur.Type != s.Type {
		return nil, errors.New("Cannot change a Send's type")
	}
	d := *s
	d.ID = cur.ID
	if len(d.KeyMaterial) == 0 {
		d.KeyMaterial = cur.KeyMaterial
	}
	setSendPassword(&d, password)
	if d.Password == nil && cur.Password != nil {
		at := vault.SendAuthPassword
		d.AuthType = &at
	}
	enc, err := v.EncryptSend(&d)
	if err != nil {
		return nil, err
	}
	body := sendBody(enc)
	body["file"] = enc.File
	var raw json.RawMessage
	if err := c.api().Do(ctx, http.MethodPut, "/sends/"+d.ID, body, &raw); err != nil {
		return nil, err
	}
	return c.cacheSend(v, raw)
}

// RemoveSendPassword removes the password protection of a Send.
func (c *Client) RemoveSendPassword(ctx context.Context, id string) (*vault.DecryptedSend, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return nil, err
	}
	var raw json.RawMessage
	if err := c.api().Do(ctx, http.MethodPut, "/sends/"+id+"/remove-password", nil, &raw); err != nil {
		return nil, err
	}
	return c.cacheSend(v, raw)
}

// DeleteSend deletes a Send.
func (c *Client) DeleteSend(ctx context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, err := c.open()
	if err != nil {
		return err
	}
	found := false
	for _, s := range v.Sends() {
		found = found || s.ID == id
	}
	if !found {
		return ErrNotFound
	}
	if err := c.api().Do(ctx, http.MethodDelete, "/sends/"+id, nil, nil); err != nil {
		return err
	}
	_ = c.st.Account.DeleteVaultObject("sends", id)
	return c.save()
}

func (c *Client) cacheSend(v *vault.Vault, raw json.RawMessage) (*vault.DecryptedSend, error) {
	var s vault.Send
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	if err := c.st.Account.UpsertVaultObject("sends", raw); err != nil {
		return nil, err
	}
	if err := c.save(); err != nil {
		return nil, err
	}
	material, err := crypto.DecryptBytes(v.UserKey, s.Key)
	if err != nil {
		return nil, err
	}
	return vault.DecryptSendWith(s, material), nil
}

// --- receive ---

// ReceiveOptions configure ReceiveSend.
type ReceiveOptions struct {
	// Password for password protected Sends.
	Password string
	// AllowForeignHost permits accessing Sends hosted on a server other
	// than the configured one.
	AllowForeignHost bool
}

// ReceivedSend is a decrypted Send accessed through its URL.
type ReceivedSend struct {
	*vault.DecryptedSend
	file func(ctx context.Context) ([]byte, error)
}

// File downloads and decrypts the content of a file Send.
func (r *ReceivedSend) File(ctx context.Context) ([]byte, error) {
	if r.Type != vault.SendTypeFile || r.DecryptedSend.File == nil {
		return nil, errors.New("Not a file Send.")
	}
	return r.file(ctx)
}

// ReceiveSend accesses a Send by its URL. No login is needed.
func (c *Client) ReceiveSend(ctx context.Context, sendURL string, opts ReceiveOptions) (*ReceivedSend, error) {
	c.mu.Lock()
	env, deviceID := c.st.Environment, c.st.DeviceID
	c.mu.Unlock()

	u, err := url.Parse(sendURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, errors.New("Failed to parse the provided Send url")
	}
	origin := u.Scheme + "://" + u.Host
	apiURL, identityURL := origin+"/api", origin+"/identity"
	if wv, _ := url.Parse(env.WebVaultURL()); wv != nil && origin == wv.Scheme+"://"+wv.Host {
		apiURL, identityURL = env.APIURL(), env.IdentityURL()
	} else if !opts.AllowForeignHost {
		return nil, ErrSendForeignHost
	}
	parts := strings.Split(strings.TrimPrefix(u.Fragment, "/"), "/")
	if len(parts) < 2 || strings.TrimSpace(parts[len(parts)-2]) == "" || strings.TrimSpace(parts[len(parts)-1]) == "" {
		return nil, errors.New("Failed to parse url, the url provided is not a valid Send url")
	}
	accessID, keyPart := parts[len(parts)-2], parts[len(parts)-1]
	material, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(keyPart, "="))
	if err != nil {
		return nil, errors.New("Failed to parse url, the url provided is not a valid Send url")
	}
	cl := &api.Client{
		HTTP: c.opts.HTTPClient, Env: state.Environment{API: apiURL, Identity: identityURL}, DeviceID: deviceID,
		AllowHTTP: c.opts.AllowInsecureHTTP, Debug: c.opts.DebugLog,
	}

	token, err := sendAccessToken(ctx, cl, accessID, "")
	var se *sendAccessError
	if errors.As(err, &se) {
		switch se.kind {
		case "send_id_invalid":
			return nil, ErrNotFound
		case "email_required", "email_invalid", "otp_required":
			return nil, ErrSendEmailVerification
		case "password_hash_b64_required":
			if opts.Password == "" {
				return nil, ErrSendPasswordRequired
			}
			token, err = sendAccessToken(ctx, cl, accessID, vault.SendPasswordHash(opts.Password, material))
			if errors.As(err, &se) && se.kind == "password_hash_b64_invalid" {
				return nil, ErrSendInvalidPassword
			}
		default:
			return nil, errors.New("Authentication failed")
		}
	}
	if err != nil {
		return nil, err
	}
	cl.Tokens = &state.Tokens{AccessToken: token, ExpiresAt: time.Now().Add(time.Hour)}
	var raw json.RawMessage
	if err := cl.Do(ctx, http.MethodPost, "/sends/access", nil, &raw); err != nil {
		if api.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var s vault.Send
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	d := vault.DecryptSendWith(s, material)
	r := &ReceivedSend{DecryptedSend: d}
	r.file = func(ctx context.Context) ([]byte, error) {
		var dl struct {
			URL string `json:"url"`
		}
		if err := cl.Do(ctx, http.MethodPost, "/sends/access/file/"+d.File.ID, nil, &dl); err != nil {
			return nil, err
		}
		if !strings.HasPrefix(dl.URL, origin) && !strings.HasPrefix(dl.URL, apiURL) {
			return nil, errors.New("Download blocked: the file url failed a security check.")
		}
		encData, err := cl.Download(ctx, dl.URL)
		if err != nil {
			return nil, err
		}
		plain, err := crypto.DecryptBuffer(vault.SendCryptoKey(material), encData)
		if err != nil {
			return nil, errors.New("An error occurred while saving the attachment.")
		}
		return plain, nil
	}
	return r, nil
}

type sendAccessError struct{ kind string }

func (e *sendAccessError) Error() string { return e.kind }

// sendAccessToken mints a token with the send_access grant.
func sendAccessToken(ctx context.Context, c *api.Client, sendID, passwordHash string) (string, error) {
	form := url.Values{"grant_type": {"send_access"}, "client_id": {"send"}, "scope": {"api.send.access"}, "send_id": {sendID}}
	if passwordHash != "" {
		form.Set("password_hash_b64", passwordHash)
	}
	tr, err := c.Token(ctx, form)
	if err == nil {
		return tr.AccessToken, nil
	}
	var ae *api.Error
	if errors.As(err, &ae) {
		var body struct {
			Type string `json:"send_access_error_type"`
		}
		if json.Unmarshal(ae.Body, &body) == nil && body.Type != "" {
			return "", &sendAccessError{kind: body.Type}
		}
	}
	return "", err
}
