package cli

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/yangxiang/bw/internal/api"
	"github.com/yangxiang/bw/internal/crypto"
	"github.com/yangxiang/bw/internal/output"
	"github.com/yangxiang/bw/internal/state"
	"github.com/yangxiang/bw/internal/vault"
)

// sendURL mirrors Environment.getSendUrl for self-hosted servers.
func sendURL(env state.Environment) string { return env.WebVaultURL() + "/#/send/" }

// sendInput is the JSON accepted by send create/edit (SendResponse shape).
type sendInput struct {
	ID   *string `json:"id"`
	Name *string `json:"name"`
	// Notes uses RawMessage to tell an explicit null from an absent key.
	Notes *string `json:"notes"`
	Key   *string `json:"key"`
	Type  int     `json:"type"`
	Text  *struct {
		Text   *string `json:"text"`
		Hidden *bool   `json:"hidden"`
	} `json:"text"`
	File *struct {
		FileName *string `json:"fileName"`
	} `json:"file"`
	MaxAccessCount *int     `json:"maxAccessCount"`
	DeletionDate   *string  `json:"deletionDate"`
	ExpirationDate *string  `json:"expirationDate"`
	Password       *string  `json:"password"`
	Emails         []string `json:"emails"`
	Disabled       bool     `json:"disabled"`
	HideEmail      bool     `json:"hideEmail"`
}

// parseJSDate accepts the date formats `new Date(string)` commonly sees.
func parseJSDate(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func (a *App) runSendTemplate(cmd *cobra.Command, args []string) output.Response {
	del := jsTime(time.Now().Add(7 * 24 * time.Hour))
	switch args[0] {
	case "send.text", "text":
		return output.Template(vault.SendTemplate(vault.SendTypeText, del))
	case "send.file", "file":
		return output.Template(vault.SendTemplate(vault.SendTypeFile, del))
	}
	return output.Error("Unknown template object.")
}

// runQuickSend mirrors `bw send <data>`: build a template and create it.
func (a *App) runQuickSend(cmd *cobra.Command, args []string) output.Response {
	data := ""
	if len(args) > 0 {
		data = args[0]
	} else {
		data = strings.TrimRight(readStdin(), "\n")
	}
	name := uuid.NewString()
	sendType := vault.SendTypeText
	var text, file any
	if boolean(cmd, "file") {
		abs, _ := filepath.Abs(data)
		if _, err := os.Stat(abs); err != nil {
			return output.Error("data path does not exist")
		}
		file = map[string]string{"fileName": abs}
		name = filepath.Base(abs)
		sendType = vault.SendTypeFile
	} else {
		text = map[string]any{"text": data, "hidden": boolean(cmd, "hidden")}
	}
	if changed(cmd, "name") {
		name = str(cmd, "name")
	}
	days, err := strconv.ParseFloat(str(cmd, "deleteInDays"), 64)
	if err != nil {
		days = 7
	}
	tmpl := map[string]any{
		"name": name, "type": sendType, "text": text, "file": file, "maxAccessCount": nil,
		"deletionDate":   jsTime(time.Now().Add(time.Duration(days * float64(24*time.Hour)))),
		"expirationDate": nil, "password": nil, "disabled": false, "hideEmail": false,
	}
	if changed(cmd, "notes") {
		tmpl["notes"] = str(cmd, "notes")
	}
	b, _ := json.Marshal(tmpl)
	return a.sendCreate(base64.StdEncoding.EncodeToString(b), sendCreateOptions{
		password: str(cmd, "password"), emails: str(cmd, "emails"), maxAccessCount: str(cmd, "maxAccessCount"),
	})
}

type sendCreateOptions struct {
	file, text, password, emails, maxAccessCount string
	hidden                                       bool
}

func (a *App) runSendCreate(cmd *cobra.Command, args []string) output.Response {
	encoded := ""
	if len(args) > 0 {
		encoded = args[0]
	}
	return a.sendCreate(encoded, sendCreateOptions{
		file: str(cmd, "file"), text: str(cmd, "text"), hidden: boolean(cmd, "hidden"),
		password: inheritedStr(cmd, "password"), emails: inheritedStr(cmd, "emails"),
	})
}

// inheritedStr reads a flag from the command or, like commander, its parent.
func inheritedStr(cmd *cobra.Command, name string) string {
	if v := str(cmd, name); v != "" {
		return v
	}
	if p := cmd.Parent(); p != nil && p.Flags().Lookup(name) != nil {
		v, _ := p.Flags().GetString(name)
		return v
	}
	return ""
}

func (a *App) sendCreate(encoded string, opts sendCreateOptions) output.Response {
	var in sendInput
	if r := decodeRequest(encoded, &in); r != nil {
		return *r
	}
	if in.DeletionDate == nil {
		return output.Error("Must specify a valid deletion date after the current time")
	}
	del, ok := parseJSDate(*in.DeletionDate)
	if !ok || !del.After(time.Now()) {
		return output.Error("Must specify a valid deletion date after the current time")
	}
	if in.ExpirationDate != nil {
		if _, ok := parseJSDate(*in.ExpirationDate); !ok {
			return output.Error("Unable to parse expirationDate: %s", *in.ExpirationDate)
		}
	}
	password := opts.password
	if in.Password != nil {
		password = *in.Password
	}
	if len(in.Emails) > 0 || opts.emails != "" {
		if strings.TrimSpace(password) != "" {
			return output.Error("--password and --emails are mutually exclusive.")
		}
		return output.Error("Email-protected Sends are not supported by this CLI.")
	}
	if in.MaxAccessCount == nil && opts.maxAccessCount != "" {
		if n, err := strconv.Atoi(opts.maxAccessCount); err == nil {
			in.MaxAccessCount = &n
		}
	}
	v, resp := a.openVault()
	if resp != nil {
		return *resp
	}
	d := &vault.DecryptedSend{KeyMaterial: crypto.RandomBytes(16)}
	d.Type = in.Type
	d.Name = deref(in.Name)
	d.Notes = in.Notes
	d.MaxAccessCount = in.MaxAccessCount
	d.DeletionDate = del.UTC().Format(time.RFC3339Nano)
	d.ExpirationDate = in.ExpirationDate
	d.Disabled, d.HideEmail = in.Disabled, in.HideEmail
	var fileData []byte
	switch in.Type {
	case vault.SendTypeFile:
		if a.serve {
			return output.Error("Creating a file-based Send is unsupported through the `serve` command at this time.")
		}
		path := opts.file
		if in.File != nil && in.File.FileName != nil {
			path = *in.File.FileName
		}
		if path == "" {
			return output.Error("Must specify a file to Send either with the --file option or in the request JSON.")
		}
		var err error
		if fileData, err = os.ReadFile(path); err != nil {
			return output.Error("%v", err)
		}
		d.File = &vault.SendFile{FileName: filepath.Base(path)}
	case vault.SendTypeText:
		var text *string
		hidden := opts.hidden
		if opts.text != "" {
			t := opts.text
			text = &t
		}
		if in.Text != nil {
			if in.Text.Text != nil {
				text = in.Text.Text
			}
			if in.Text.Hidden != nil {
				hidden = *in.Text.Hidden
			}
		}
		if text == nil {
			return output.Error("Must specify text content to Send either with the --text option or in the request JSON.")
		}
		d.Text = &vault.SendText{Text: text, Hidden: hidden}
	case 2:
		return output.Error("Item type Send functionality not yet available")
	default:
		return output.Error("Unknown Send type %s. Valid types are: file, text", sendTypeName(in.Type))
	}
	if strings.TrimSpace(password) != "" {
		h := vault.SendPasswordHash(password, d.KeyMaterial)
		d.Password = &h
		at := vault.SendAuthPassword
		d.AuthType = &at
	} else {
		at := vault.SendAuthNone
		d.AuthType = &at
	}
	return a.saveSend(v, d, fileData, true)
}

func sendTypeName(t int) string {
	switch t {
	case 0:
		return "Text"
	case 1:
		return "File"
	}
	return "undefined"
}

// saveSend encrypts and uploads a Send (create when isNew), then caches and prints it.
func (a *App) saveSend(v *vault.Vault, d *vault.DecryptedSend, fileData []byte, isNew bool) output.Response {
	c, err := a.client()
	if err != nil {
		return output.Error("%v", err)
	}
	enc, err := v.EncryptSend(d)
	if err != nil {
		return output.Error("%v", err)
	}
	body := map[string]any{
		"type": enc.Type, "name": enc.Name, "notes": enc.Notes, "key": enc.Key,
		"maxAccessCount": enc.MaxAccessCount, "expirationDate": enc.ExpirationDate,
		"deletionDate": enc.DeletionDate, "text": enc.Text, "password": enc.Password,
		"disabled": enc.Disabled, "hideEmail": enc.HideEmail, "authType": enc.AuthType,
	}
	var raw json.RawMessage
	switch {
	case !isNew:
		body["file"] = enc.File
		err = c.Do(http.MethodPut, "/sends/"+d.ID, body, &raw)
	case enc.Type == vault.SendTypeFile:
		var encFile []byte
		if encFile, err = crypto.EncryptBuffer(vault.SendCryptoKey(d.KeyMaterial), fileData); err != nil {
			return output.Error("%v", err)
		}
		body["file"] = map[string]string{"fileName": enc.File.FileName}
		body["fileLength"] = len(encFile)
		var up struct {
			FileUploadType int             `json:"fileUploadType"`
			SendResponse   json.RawMessage `json:"sendResponse"`
		}
		if err = c.Do(http.MethodPost, "/sends/file/v2", body, &up); err != nil {
			break
		}
		var created vault.Send
		if err = json.Unmarshal(up.SendResponse, &created); err != nil {
			break
		}
		if up.FileUploadType != 0 {
			err = errors.New("unsupported Send file upload type")
			break
		}
		mp, merr := api.Multipart(nil, "data", enc.File.FileName, encFile)
		if merr != nil {
			return output.Error("%v", merr)
		}
		if err = c.SendRaw(http.MethodPost, c.Env.APIURL()+"/sends/"+created.ID+"/file/"+created.File.ID, mp, nil); err != nil {
			_ = c.Do(http.MethodDelete, "/sends/"+created.ID, nil, nil)
			break
		}
		err = c.Get("/sends/"+created.ID, &raw)
	default:
		err = c.Do(http.MethodPost, "/sends", body, &raw)
	}
	if err != nil {
		return errResp(err)
	}
	return a.cacheAndPrintSend(v, raw)
}

func (a *App) cacheAndPrintSend(v *vault.Vault, raw json.RawMessage) output.Response {
	var s vault.Send
	if err := json.Unmarshal(raw, &s); err != nil {
		return output.Error("%v", err)
	}
	st, _ := a.state()
	if err := st.Account.UpsertVaultObject("sends", raw); err != nil {
		return output.Error("%v", err)
	}
	if err := st.Save(); err != nil {
		return output.Error("%v", err)
	}
	material, err := crypto.DecryptBytes(v.UserKey, s.Key)
	if err != nil {
		return output.Error("%v", err)
	}
	return output.Success(vault.SendOutput(vault.DecryptSendWith(s, material), sendURL(st.Environment)))
}

func (a *App) runSendList(cmd *cobra.Command, args []string) output.Response {
	v, resp := a.openVault()
	if resp != nil {
		return *resp
	}
	st, _ := a.state()
	out := []vault.SendResponse{}
	for _, s := range v.Sends() {
		out = append(out, vault.SendOutput(s, sendURL(st.Environment)))
	}
	return output.List(out)
}

// findSend mirrors SendGetCommand.getSendView.
func findSend(v *vault.Vault, id string) ([]*vault.DecryptedSend, bool) {
	sends := v.Sends()
	if isGUID(id) {
		for _, s := range sends {
			if s.ID == strings.ToLower(id) {
				return []*vault.DecryptedSend{s}, true
			}
		}
		return nil, false
	}
	if strings.TrimSpace(id) == "" {
		return nil, false
	}
	m := vault.SearchSends(sends, id)
	return m, len(m) > 0
}

func (a *App) runSendGet(cmd *cobra.Command, args []string) output.Response {
	v, resp := a.openVault()
	if resp != nil {
		return *resp
	}
	return a.sendGet(v, args[0], str(cmd, "output"), boolean(cmd, "text"))
}

func (a *App) sendGet(v *vault.Vault, id, outPath string, text bool) output.Response {
	if a.serve && !isGUID(id) {
		return output.Error("`%s` is not a GUID.", id)
	}
	sends, ok := findSend(v, id)
	if !ok {
		return notFound()
	}
	if text {
		var withText []*vault.DecryptedSend
		for _, s := range sends {
			if s.Text != nil {
				withText = append(withText, s)
			}
		}
		sends = withText
	}
	if len(sends) > 1 {
		return multipleResults(mapIDs(sends, func(s *vault.DecryptedSend) string { return s.ID }))
	}
	if len(sends) == 0 {
		return notFound()
	}
	if text {
		os.Stdout.WriteString(deref(sends[0].Text.Text))
		return output.Success(nil)
	}
	st, _ := a.state()
	return output.Success(vault.SendOutput(sends[0], sendURL(st.Environment)))
}

func (a *App) runSendEdit(cmd *cobra.Command, args []string) output.Response {
	encoded := ""
	if len(args) > 0 {
		encoded = args[0]
	}
	var in sendInput
	if r := decodeRequest(encoded, &in); r != nil {
		return *r
	}
	if id := str(cmd, "itemid"); id != "" {
		in.ID = &id
	}
	if p := inheritedStr(cmd, "password"); p != "" {
		in.Password = &p
	}
	if in.Password != nil && *in.Password == "" {
		in.Password = nil
	}
	if e := inheritedStr(cmd, "emails"); e != "" || len(in.Emails) > 0 {
		if in.Password != nil && strings.TrimSpace(*in.Password) != "" {
			return output.Error("--password and --emails are mutually exclusive.")
		}
		return output.Error("Email-protected Sends are not supported by this CLI.")
	}
	if in.ID == nil || *in.ID == "" {
		return output.Error("`itemid` was not provided.")
	}
	id := strings.ToLower(*in.ID)
	v, resp := a.openVault()
	if resp != nil {
		return *resp
	}
	var cur *vault.DecryptedSend
	for _, s := range v.Sends() {
		if s.ID == id {
			cur = s
		}
	}
	if cur == nil {
		return notFound()
	}
	if cur.Type != in.Type {
		return output.Error("Cannot change a Send's type")
	}
	// SendResponse.toView: request values replace the stored ones.
	d := *cur
	d.Name = deref(in.Name)
	d.Notes = in.Notes
	if in.Key != nil {
		if k, err := base64.StdEncoding.DecodeString(*in.Key); err == nil && len(k) > 0 {
			d.KeyMaterial = k
		}
	} else {
		d.KeyMaterial = crypto.RandomBytes(16)
	}
	if in.Text != nil && d.Type == vault.SendTypeText {
		d.Text = &vault.SendText{Text: in.Text.Text}
		if in.Text.Hidden != nil {
			d.Text.Hidden = *in.Text.Hidden
		}
	}
	d.MaxAccessCount = in.MaxAccessCount
	if in.DeletionDate != nil {
		if t, ok := parseJSDate(*in.DeletionDate); ok {
			d.DeletionDate = t.UTC().Format(time.RFC3339Nano)
		}
	}
	d.ExpirationDate = in.ExpirationDate
	d.Disabled, d.HideEmail = in.Disabled, in.HideEmail
	d.Password = nil
	at := vault.SendAuthNone
	if in.Password != nil && strings.TrimSpace(*in.Password) != "" {
		h := vault.SendPasswordHash(*in.Password, d.KeyMaterial)
		d.Password = &h
		at = vault.SendAuthPassword
	} else if cur.Password != nil {
		at = vault.SendAuthPassword
	}
	d.AuthType = &at
	return a.saveSend(v, &d, nil, false)
}

func (a *App) runSendRemovePassword(cmd *cobra.Command, args []string) output.Response {
	v, resp := a.openVault()
	if resp != nil {
		return *resp
	}
	c, err := a.client()
	if err != nil {
		return output.Error("%v", err)
	}
	var raw json.RawMessage
	if err := c.Do(http.MethodPut, "/sends/"+args[0]+"/remove-password", nil, &raw); err != nil {
		return errResp(err)
	}
	return a.cacheAndPrintSend(v, raw)
}

func (a *App) runSendDelete(cmd *cobra.Command, args []string) output.Response {
	v, resp := a.openVault()
	if resp != nil {
		return *resp
	}
	found := false
	for _, s := range v.Sends() {
		found = found || s.ID == args[0]
	}
	if !found {
		return notFound()
	}
	c, err := a.client()
	if err != nil {
		return output.Error("%v", err)
	}
	if err := c.Do(http.MethodDelete, "/sends/"+args[0], nil, nil); err != nil {
		return errResp(err)
	}
	st, _ := a.state()
	_ = st.Account.DeleteVaultObject("sends", args[0])
	if err := st.Save(); err != nil {
		return output.Error("%v", err)
	}
	return output.Success(nil)
}

// --- receive ---

type sendAccessError struct{ kind string }

func (e *sendAccessError) Error() string { return e.kind }

func (a *App) runReceive(cmd *cobra.Command, args []string) output.Response {
	u, err := url.Parse(args[0])
	if err != nil || u.Scheme == "" || u.Host == "" {
		return output.Error("Failed to parse the provided Send url")
	}
	st, err := a.state()
	if err != nil {
		return output.Error("%v", err)
	}
	env := st.Environment
	origin := u.Scheme + "://" + u.Host
	apiURL, identityURL := origin+"/api", origin+"/identity"
	webVault, _ := url.Parse(env.WebVaultURL())
	if webVault != nil && origin == webVault.Scheme+"://"+webVault.Host {
		apiURL, identityURL = env.APIURL(), env.IdentityURL()
	} else {
		if a.noInteraction {
			return output.Error("Send access will not be attempted: the domain in the Send URL does not match the configured domain. Run interactively in order to override.")
		}
		ans := prompt("You are attempting to access a Send hosted on " + origin + " but your CLI is configured for " +
			env.WebVaultURL() + ". Do not proceed if you do not trust " + origin + ". Do you want to proceed? (y/N)")
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ans)), "y") {
			return output.Error("Send access cancelled.")
		}
	}
	parts := strings.Split(strings.TrimPrefix(u.Fragment, "/"), "/")
	if len(parts) < 2 || strings.TrimSpace(parts[len(parts)-2]) == "" || strings.TrimSpace(parts[len(parts)-1]) == "" {
		return output.Error("Failed to parse url, the url provided is not a valid Send url")
	}
	accessID, keyPart := parts[len(parts)-2], parts[len(parts)-1]
	material, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(keyPart, "="))
	if err != nil {
		return output.Error("Failed to parse url, the url provided is not a valid Send url")
	}
	c := &api.Client{Env: state.Environment{API: apiURL, Identity: identityURL}, DeviceID: st.DeviceID}

	getPassword := func() (string, *output.Response) {
		pw := str(cmd, "password")
		if pw == "" {
			if f := str(cmd, "passwordfile"); f != "" {
				pw, _ = readFirstLine(f)
			} else if e := str(cmd, "passwordenv"); e != "" {
				pw = os.Getenv(e)
			}
		}
		if pw == "" && !a.noInteraction {
			pw = promptSecret("Send password:")
		}
		if pw == "" {
			r := output.Error("Password required")
			return "", &r
		}
		return pw, nil
	}

	token, err := sendAccessToken(c, accessID, "")
	var raw json.RawMessage
	var legacy bool
	switch e := err.(type) {
	case nil:
	case *sendAccessError:
		switch e.kind {
		case "send_id_invalid":
			return notFound()
		case "email_required", "email_invalid", "otp_required":
			if a.noInteraction {
				return output.Error("Email verification required. Run in interactive mode.")
			}
			return output.Error("Email-verified Sends are not supported by this CLI.")
		case "password_hash_b64_required":
			pw, r := getPassword()
			if r != nil {
				return *r
			}
			token, err = sendAccessToken(c, accessID, vault.SendPasswordHash(pw, material))
			if se, ok := err.(*sendAccessError); ok && se.kind == "password_hash_b64_invalid" {
				return output.Error("Invalid password")
			}
			if err != nil {
				return errResp(err)
			}
		default:
			return output.Error("Authentication failed")
		}
	default:
		// Servers without the send_access grant: use the legacy access endpoint.
		legacy = true
	}
	var pwHash string
	if legacy {
		err = c.SendAnonymous(http.MethodPost, "/sends/access/"+accessID, map[string]any{}, &raw)
		if ae, ok := err.(*api.Error); ok && ae.Status == http.StatusUnauthorized {
			pw, r := getPassword()
			if r != nil {
				return *r
			}
			pwHash = vault.SendPasswordHash(pw, material)
			err = c.SendAnonymous(http.MethodPost, "/sends/access/"+accessID, map[string]any{"password": pwHash}, &raw)
			if ae, ok := err.(*api.Error); ok && (ae.Status == http.StatusBadRequest || ae.Status == http.StatusUnauthorized) {
				return output.Error("Invalid password")
			}
		}
	} else {
		c.Tokens = &state.Tokens{AccessToken: token, ExpiresAt: time.Now().Add(time.Hour)}
		err = c.Do(http.MethodPost, "/sends/access", nil, &raw)
	}
	if err != nil {
		if api.IsNotFound(err) {
			return notFound()
		}
		return errResp(err)
	}
	var s vault.Send
	if err := json.Unmarshal(raw, &s); err != nil {
		return output.Error("%v", err)
	}
	d := vault.DecryptSendWith(s, material)
	if boolean(cmd, "obj") {
		r := vault.SendAccessResponse{Object: "send-access", ID: d.ID, Name: d.Name, Type: d.Type}
		if d.Type == vault.SendTypeText && d.Text != nil {
			r.Text = &vault.SendTextResponse{Text: d.Text.Text, Hidden: d.Text.Hidden}
		}
		if d.Type == vault.SendTypeFile && d.File != nil {
			r.File = &vault.SendFileResponse{ID: d.File.ID, Size: string(d.File.Size), SizeName: d.File.SizeName, FileName: d.File.FileName}
		}
		return output.Success(r)
	}
	switch d.Type {
	case vault.SendTypeText:
		if d.Text != nil {
			os.Stdout.WriteString(deref(d.Text.Text))
		}
		return output.Success(nil)
	case vault.SendTypeFile:
		var dl struct {
			URL string `json:"url"`
		}
		if legacy {
			err = c.SendAnonymous(http.MethodPost, "/sends/"+d.ID+"/access/file/"+d.File.ID, map[string]any{"password": nullable(pwHash)}, &dl)
		} else {
			err = c.Do(http.MethodPost, "/sends/access/file/"+d.File.ID, nil, &dl)
		}
		if err != nil {
			return errResp(err)
		}
		if !strings.HasPrefix(dl.URL, origin) && !strings.HasPrefix(dl.URL, apiURL) {
			return output.Error("Download blocked: the file url failed a security check.")
		}
		encData, err := c.Download(dl.URL)
		if err != nil {
			return errResp(err)
		}
		plain, err := crypto.DecryptBuffer(vault.SendCryptoKey(material), encData)
		if err != nil {
			return output.Error("An error occurred while saving the attachment.")
		}
		return a.saveResultToFile(plain, str(cmd, "output"), filepath.Base(d.File.FileName))
	}
	return output.Success(vault.SendAccessResponse{Object: "send-access", ID: d.ID, Name: d.Name, Type: d.Type})
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// sendAccessToken mints a token with the send_access grant.
func sendAccessToken(c *api.Client, sendID, passwordHash string) (string, error) {
	form := url.Values{"grant_type": {"send_access"}, "client_id": {"send"}, "scope": {"api.send.access"}, "send_id": {sendID}}
	if passwordHash != "" {
		form.Set("password_hash_b64", passwordHash)
	}
	tr, err := c.Token(form)
	if err == nil {
		return tr.AccessToken, nil
	}
	if ae, ok := err.(*api.Error); ok {
		var body struct {
			Type string `json:"send_access_error_type"`
		}
		if json.Unmarshal(ae.Body, &body) == nil && body.Type != "" {
			return "", &sendAccessError{kind: body.Type}
		}
	}
	return "", err
}
