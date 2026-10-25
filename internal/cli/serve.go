package cli

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/yangxiang/bw/internal/output"
)

func (a *App) serveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start a RESTful API webserver.",
		Long:  "Start a RESTful API webserver.\n\nNotes:\n  Default hostname is `localhost`.\n  Use hostname `all` for no hostname binding.\n  Default port is `8087`.",
		Example: `  bw serve
  bw serve --port 8080
  bw serve --hostname bwapi.mydomain.com --port 80`,
		Args: cobra.NoArgs,
		Run:  a.action(a.runServe),
	}
	f := cmd.Flags()
	f.String("hostname", "localhost", "The hostname to bind your API webserver to.")
	f.String("port", "8087", "The port to run your API webserver on.")
	f.Bool("disable-origin-protection", false, "If set, allows requests with origin header. Warning, this option exists for backwards compatibility reasons and exposes your environment to known CSRF attacks.")
	return cmd
}

// server runs CLI commands on behalf of HTTP requests.
type server struct {
	mu      sync.Mutex
	session string
}

// blockedQueryFlags may never be set through the query string.
var blockedQueryFlags = map[string]bool{
	"session": true, "raw": true, "response": true, "quiet": true, "pretty": true,
	"cleanexit": true, "nointeraction": true, "passwordfile": true, "passwordenv": true,
	"output": true, "file": true, "help": true,
}

// run executes a CLI invocation in capture mode. Request-derived positional
// values follow "--" so they can never be parsed as flags.
func (s *server) run(path, flags []string, pos ...string) output.Response {
	args := append(append(append([]string(nil), path...), flags...), "--")
	args = append(args, pos...)
	app := &App{serve: true, noInteraction: true, session: s.session}
	root := app.newRootCmd()
	root.SetArgs(args)
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	if err := root.Execute(); err != nil {
		return output.Error("%v", err)
	}
	if app.captured == nil {
		return output.Success(nil)
	}
	return *app.captured
}

// flags converts query parameters into flags known by the target command.
func (s *server) flags(path []string, q map[string][]string) []string {
	app := &App{serve: true}
	target, _, err := app.newRootCmd().Find(path)
	if err != nil {
		return nil
	}
	var args []string
	for k, vals := range q {
		if blockedQueryFlags[strings.ToLower(k)] {
			continue
		}
		f := target.Flags().Lookup(k)
		if f == nil {
			f = target.Flags().Lookup(strings.ToLower(k))
		}
		if f == nil {
			continue
		}
		v := ""
		if len(vals) > 0 {
			v = vals[0]
		}
		if f.Value.Type() == "bool" {
			// CliUtils.convertBooleanOption: any present value is true.
			args = append(args, "--"+f.Name)
		} else {
			args = append(args, "--"+f.Name+"="+v)
		}
	}
	return args
}

func (s *server) locked() *output.Response {
	app := &App{serve: true, session: s.session}
	if _, r := app.requireAuthed(); r != nil {
		return r
	}
	if !app.isUnlocked() {
		r := output.Error("Vault is locked.")
		return &r
	}
	return nil
}

func writeResponse(w http.ResponseWriter, r *http.Request, resp output.Response) {
	if f, ok := resp.Data.(output.FileResponse); ok && resp.Success {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", f.FileName))
		w.Header().Set("Content-Length", strconv.Itoa(len(f.Data)))
		_, _ = w.Write(f.Data)
		return
	}
	indent := ""
	if _, ok := r.URL.Query()["pretty"]; ok {
		indent = "  "
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if !resp.Success {
		w.WriteHeader(http.StatusBadRequest)
	}
	_, _ = io.WriteString(w, output.JSON(resp, indent))
}

// bodyArg returns the JSON request body as a base64 encodedJson argument.
func bodyArg(r *http.Request) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		return "", err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		// koa-bodyparser yields {} for an empty body.
		b = []byte("{}")
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func (s *server) handler(protectOrigin bool, allowedHosts map[string]bool) http.Handler {
	mux := http.NewServeMux()
	locked := func(h func(w http.ResponseWriter, r *http.Request) output.Response) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			s.mu.Lock()
			defer s.mu.Unlock()
			if resp := s.locked(); resp != nil {
				writeResponse(w, r, *resp)
				return
			}
			writeResponse(w, r, h(w, r))
		}
	}
	open := func(h func(w http.ResponseWriter, r *http.Request) output.Response) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			s.mu.Lock()
			defer s.mu.Unlock()
			writeResponse(w, r, h(w, r))
		}
	}
	q := func(r *http.Request) map[string][]string { return r.URL.Query() }
	// withBody appends the request body (base64 JSON) to the positionals.
	withBody := func(r *http.Request, pos ...string) ([]string, *output.Response) {
		b, err := bodyArg(r)
		if err != nil {
			e := output.Error("%v", err)
			return nil, &e
		}
		if b != "" {
			pos = append(pos, b)
		}
		return pos, nil
	}
	cmdFlags := func(r *http.Request, path ...string) []string { return s.flags(path, q(r)) }

	mux.HandleFunc("GET /generate", open(func(w http.ResponseWriter, r *http.Request) output.Response {
		return s.run([]string{"generate"}, cmdFlags(r, "generate"))
	}))
	mux.HandleFunc("GET /status", open(func(w http.ResponseWriter, r *http.Request) output.Response {
		return s.run([]string{"status"}, nil)
	}))
	mux.HandleFunc("GET /list/object/{object}", locked(func(w http.ResponseWriter, r *http.Request) output.Response {
		if r.PathValue("object") == "send" {
			return s.run([]string{"send", "list"}, nil)
		}
		return s.run([]string{"list"}, cmdFlags(r, "list"), r.PathValue("object"))
	}))
	mux.HandleFunc("GET /send/list", locked(func(w http.ResponseWriter, r *http.Request) output.Response {
		return s.run([]string{"send", "list"}, nil)
	}))
	mux.HandleFunc("POST /sync", open(func(w http.ResponseWriter, r *http.Request) output.Response {
		return s.run([]string{"sync"}, cmdFlags(r, "sync"))
	}))
	mux.HandleFunc("POST /lock", open(func(w http.ResponseWriter, r *http.Request) output.Response {
		resp := s.run([]string{"lock"}, nil)
		if resp.Success {
			s.session = ""
		}
		return resp
	}))
	mux.HandleFunc("POST /unlock", open(func(w http.ResponseWriter, r *http.Request) output.Response {
		var body struct {
			Password *string `json:"password"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
		var pos []string
		if body.Password != nil && *body.Password != "" {
			pos = append(pos, *body.Password)
		}
		resp := s.run([]string{"unlock"}, nil, pos...)
		if m, ok := resp.Data.(output.MessageResponse); ok && resp.Success && m.Raw != nil {
			s.session = *m.Raw
		}
		return resp
	}))
	mux.HandleFunc("POST /confirm/{object}/{id}", locked(func(w http.ResponseWriter, r *http.Request) output.Response {
		return s.run([]string{"confirm"}, cmdFlags(r, "confirm"), r.PathValue("object"), r.PathValue("id"))
	}))
	mux.HandleFunc("POST /restore/{object}/{id}", locked(func(w http.ResponseWriter, r *http.Request) output.Response {
		return s.run([]string{"restore"}, nil, r.PathValue("object"), r.PathValue("id"))
	}))
	mux.HandleFunc("POST /archive/{object}/{id}", locked(func(w http.ResponseWriter, r *http.Request) output.Response {
		return s.run([]string{"archive"}, nil, r.PathValue("object"), r.PathValue("id"))
	}))
	mux.HandleFunc("POST /move/{id}/{organizationId}", locked(func(w http.ResponseWriter, r *http.Request) output.Response {
		pos, e := withBody(r, r.PathValue("id"), r.PathValue("organizationId"))
		if e != nil {
			return *e
		}
		return s.run([]string{"move"}, nil, pos...)
	}))
	mux.HandleFunc("POST /attachment", locked(func(w http.ResponseWriter, r *http.Request) output.Response {
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			return output.Error("File not provided.")
		}
		file, hdr, err := r.FormFile("file")
		if err != nil {
			return output.Error("File not provided.")
		}
		defer file.Close()
		name := filepath.Base(hdr.Filename)
		if strings.TrimSpace(name) == "" || name == "." || name == "/" {
			return output.Error("File name not provided.")
		}
		dir, err := os.MkdirTemp("", "bw-serve-")
		if err != nil {
			return output.Error("%v", err)
		}
		defer os.RemoveAll(dir)
		path := filepath.Join(dir, name)
		out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		if err != nil {
			return output.Error("%v", err)
		}
		if _, err := io.Copy(out, file); err != nil {
			out.Close()
			return output.Error("%v", err)
		}
		out.Close()
		flags := append(cmdFlags(r, "create"), "--file="+path)
		return s.run([]string{"create"}, flags, "attachment")
	}))
	mux.HandleFunc("POST /send/{id}/remove-password", locked(func(w http.ResponseWriter, r *http.Request) output.Response {
		return s.run([]string{"send", "remove-password"}, nil, r.PathValue("id"))
	}))
	mux.HandleFunc("POST /object/{object}", locked(func(w http.ResponseWriter, r *http.Request) output.Response {
		if r.PathValue("object") == "send" {
			pos, e := withBody(r)
			if e != nil {
				return *e
			}
			return s.run([]string{"send", "create"}, cmdFlags(r, "send", "create"), pos...)
		}
		pos, e := withBody(r, r.PathValue("object"))
		if e != nil {
			return *e
		}
		return s.run([]string{"create"}, cmdFlags(r, "create"), pos...)
	}))
	mux.HandleFunc("PUT /object/{object}/{id}", locked(func(w http.ResponseWriter, r *http.Request) output.Response {
		if r.PathValue("object") == "send" {
			pos, e := withBody(r)
			if e != nil {
				return *e
			}
			return s.run([]string{"send", "edit"}, []string{"--itemid=" + r.PathValue("id")}, pos...)
		}
		pos, e := withBody(r, r.PathValue("object"), r.PathValue("id"))
		if e != nil {
			return *e
		}
		return s.run([]string{"edit"}, cmdFlags(r, "edit"), pos...)
	}))
	mux.HandleFunc("GET /object/{object}/{id}", locked(func(w http.ResponseWriter, r *http.Request) output.Response {
		if r.PathValue("object") == "send" {
			return s.run([]string{"send", "get"}, nil, r.PathValue("id"))
		}
		return s.run([]string{"get"}, cmdFlags(r, "get"), r.PathValue("object"), r.PathValue("id"))
	}))
	mux.HandleFunc("DELETE /object/{object}/{id}", locked(func(w http.ResponseWriter, r *http.Request) output.Response {
		if r.PathValue("object") == "send" {
			return s.run([]string{"send", "delete"}, nil, r.PathValue("id"))
		}
		return s.run([]string{"delete"}, cmdFlags(r, "delete"), r.PathValue("object"), r.PathValue("id"))
	}))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if protectOrigin {
			if allowedHosts != nil && !allowedHosts[strings.ToLower(r.Host)] {
				fmt.Fprintf(os.Stderr, "Blocking request with disallowed Host %q\n", r.Host)
				plainStatus(w, http.StatusForbidden)
				return
			}
			if _, ok := r.Header["Origin"]; ok {
				fmt.Fprintf(os.Stderr, "Blocking request from %q\n", r.Header.Get("Origin"))
				plainStatus(w, http.StatusForbidden)
				return
			}
		}
		if _, pattern := mux.Handler(r); pattern == "" {
			plainStatus(w, http.StatusNotFound)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// plainStatus writes a koa-style plain text status body ("Forbidden", "Not Found").
func plainStatus(w http.ResponseWriter, code int) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	_, _ = io.WriteString(w, http.StatusText(code))
}

// allowedHosts mirrors buildServeAllowedHosts.
func allowedHosts(hostname string, port int) map[string]bool {
	p := strconv.Itoa(port)
	entries := []string{"localhost:" + p, "127.0.0.1:" + p, "[::1]:" + p, hostname + ":" + p}
	if port == 80 || port == 443 {
		entries = append(entries, "localhost", "127.0.0.1", "[::1]", hostname)
	}
	m := map[string]bool{}
	for _, e := range entries {
		m[strings.ToLower(e)] = true
	}
	return m
}

func (a *App) runServe(cmd *cobra.Command, args []string) output.Response {
	protect := !boolean(cmd, "disable-origin-protection")
	port, err := strconv.Atoi(str(cmd, "port"))
	if err != nil || port == 0 {
		port = 8087
	}
	hostname := str(cmd, "hostname")
	if hostname == "" {
		hostname = "localhost"
	}
	var hosts map[string]bool
	if hostname != "all" {
		hosts = allowedHosts(hostname, port)
	}
	mode := "origin protection"
	if !protect {
		mode = "no origin protection"
	}
	fmt.Fprintf(os.Stderr, "Starting server on %s:%d with %s\n", hostname, port, mode)
	serveMode = true
	s := &server{session: a.session}
	handler := s.handler(protect, hosts)

	var ln net.Listener
	desc := hostname + ":" + strconv.Itoa(port)
	switch {
	case strings.HasPrefix(hostname, "unix://"):
		desc = hostname
		ln, err = net.Listen("unix", strings.TrimPrefix(hostname, "unix://"))
	case strings.HasPrefix(hostname, "fd+"):
		return output.Error("Cannot serve on %s: file descriptor listeners are not supported", hostname)
	case hostname == "all":
		ln, err = net.Listen("tcp", ":"+strconv.Itoa(port))
	default:
		ln, err = net.Listen("tcp", net.JoinHostPort(hostname, strconv.Itoa(port)))
	}
	if err != nil {
		return output.Error("Cannot serve on %s: %v", desc, err)
	}
	fmt.Fprintln(os.Stderr, "Listening on "+desc)
	if err := http.Serve(ln, handler); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return output.Error("Cannot serve on %s: %v", desc, err)
	}
	return output.Success(nil)
}
