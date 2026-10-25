package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/oneryx/bw"
	"github.com/oneryx/bw/internal/crypto"
	"github.com/oneryx/bw/internal/output"
	"github.com/oneryx/bw/vault"
)

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
	c, err := a.requireUnlocked()
	if err != nil {
		return errResp(err)
	}
	d := &vault.DecryptedSend{}
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
	created, err := c.CreateSend(context.Background(), d, password, fileData)
	if err != nil {
		return errResp(err)
	}
	return output.Success(vault.SendOutput(created, c.SendBaseURL()))
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

func (a *App) runSendList(cmd *cobra.Command, args []string) output.Response {
	c, err := a.requireUnlocked()
	if err != nil {
		return errResp(err)
	}
	sends, err := c.Sends()
	if err != nil {
		return errResp(err)
	}
	out := []vault.SendResponse{}
	for _, s := range sends {
		out = append(out, vault.SendOutput(s, c.SendBaseURL()))
	}
	return output.List(out)
}

// findSend mirrors SendGetCommand.getSendView.
func findSend(sends []*vault.DecryptedSend, id string) ([]*vault.DecryptedSend, bool) {
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
	c, err := a.requireUnlocked()
	if err != nil {
		return errResp(err)
	}
	return a.sendGet(c, args[0], str(cmd, "output"), boolean(cmd, "text"))
}

func (a *App) sendGet(c *bw.Client, id, outPath string, text bool) output.Response {
	if a.serve && !isGUID(id) {
		return output.Error("`%s` is not a GUID.", id)
	}
	all, err := c.Sends()
	if err != nil {
		return errResp(err)
	}
	sends, ok := findSend(all, id)
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
	return output.Success(vault.SendOutput(sends[0], c.SendBaseURL()))
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
	c, err := a.requireUnlocked()
	if err != nil {
		return errResp(err)
	}
	sends, err := c.Sends()
	if err != nil {
		return errResp(err)
	}
	var cur *vault.DecryptedSend
	for _, s := range sends {
		if s.ID == id {
			cur = s
		}
	}
	if cur == nil {
		return notFound()
	}
	// SendResponse.toView: request values replace the stored ones.
	d := *cur
	d.Type = in.Type
	d.Name = deref(in.Name)
	d.Notes = in.Notes
	d.KeyMaterial = nil
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
	updated, err := c.UpdateSend(context.Background(), &d, deref(in.Password))
	if err != nil {
		return errResp(err)
	}
	return output.Success(vault.SendOutput(updated, c.SendBaseURL()))
}

func (a *App) runSendRemovePassword(cmd *cobra.Command, args []string) output.Response {
	c, err := a.requireUnlocked()
	if err != nil {
		return errResp(err)
	}
	s, err := c.RemoveSendPassword(context.Background(), args[0])
	if err != nil {
		return errResp(err)
	}
	return output.Success(vault.SendOutput(s, c.SendBaseURL()))
}

func (a *App) runSendDelete(cmd *cobra.Command, args []string) output.Response {
	c, err := a.requireUnlocked()
	if err != nil {
		return errResp(err)
	}
	if err := c.DeleteSend(context.Background(), args[0]); err != nil {
		return errResp(err)
	}
	return output.Success(nil)
}

// --- receive ---

func (a *App) runReceive(cmd *cobra.Command, args []string) output.Response {
	c, err := a.client()
	if err != nil {
		return output.Error("%v", err)
	}
	ctx := context.Background()
	opts := bw.ReceiveOptions{Password: str(cmd, "password")}
	if opts.Password == "" {
		if f := str(cmd, "passwordfile"); f != "" {
			opts.Password, _ = readFirstLine(f)
		} else if e := str(cmd, "passwordenv"); e != "" {
			opts.Password = os.Getenv(e)
		}
	}
	r, err := c.ReceiveSend(ctx, args[0], opts)
	if errors.Is(err, bw.ErrSendForeignHost) {
		if a.noInteraction {
			return output.Error("%v Run interactively in order to override.", err)
		}
		u, _ := url.Parse(args[0])
		origin := u.Scheme + "://" + u.Host
		ans := prompt("You are attempting to access a Send hosted on " + origin + " but your CLI is configured for " +
			c.WebVaultURL() + ". Do not proceed if you do not trust " + origin + ". Do you want to proceed? (y/N)")
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ans)), "y") {
			return output.Error("Send access cancelled.")
		}
		opts.AllowForeignHost = true
		r, err = c.ReceiveSend(ctx, args[0], opts)
	}
	if errors.Is(err, bw.ErrSendPasswordRequired) && !a.noInteraction {
		if opts.Password = promptSecret("Send password:"); opts.Password != "" {
			r, err = c.ReceiveSend(ctx, args[0], opts)
		}
	}
	if errors.Is(err, bw.ErrSendEmailVerification) && a.noInteraction {
		return output.Error("Email verification required. Run in interactive mode.")
	}
	if err != nil {
		return errResp(err)
	}
	d := r.DecryptedSend
	if boolean(cmd, "obj") {
		resp := vault.SendAccessResponse{Object: "send-access", ID: d.ID, Name: d.Name, Type: d.Type}
		if d.Type == vault.SendTypeText && d.Text != nil {
			resp.Text = &vault.SendTextResponse{Text: d.Text.Text, Hidden: d.Text.Hidden}
		}
		if d.Type == vault.SendTypeFile && d.File != nil {
			resp.File = &vault.SendFileResponse{ID: d.File.ID, Size: string(d.File.Size), SizeName: d.File.SizeName, FileName: d.File.FileName}
		}
		return output.Success(resp)
	}
	switch d.Type {
	case vault.SendTypeText:
		if d.Text != nil {
			os.Stdout.WriteString(deref(d.Text.Text))
		}
		return output.Success(nil)
	case vault.SendTypeFile:
		data, err := r.File(ctx)
		if err != nil {
			return errResp(err)
		}
		return a.saveResultToFile(data, str(cmd, "output"), filepath.Base(d.File.FileName))
	}
	return output.Success(vault.SendAccessResponse{Object: "send-access", ID: d.ID, Name: d.Name, Type: d.Type})
}
