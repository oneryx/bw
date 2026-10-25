package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/oneryx/bw"
	"github.com/oneryx/bw/internal/output"
)

var stdinReader = bufio.NewReader(os.Stdin)

// prompt asks for a line of input on stderr, like inquirer's input prompt.
func prompt(msg string) string {
	if serveMode {
		return ""
	}
	fmt.Fprint(os.Stderr, "? "+msg+" ")
	line, _ := stdinReader.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

// promptSecret asks for hidden input when stdin is a terminal.
func promptSecret(msg string) string {
	if serveMode {
		return ""
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return prompt(msg)
	}
	fmt.Fprint(os.Stderr, "? "+msg+" ")
	b, _ := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr, "[hidden]")
	return string(b)
}

// readFirstLine returns the first line of a file (NodeUtils.readFirstLine).
func readFirstLine(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	line, _, _ := strings.Cut(string(b), "\n")
	return strings.TrimSuffix(line, "\r"), nil
}

// getPassword mirrors CliUtils.getPassword.
func (a *App) getPassword(password, passwordFile, passwordEnv, promptMsg string) (string, error) {
	if password == "" {
		if passwordFile != "" {
			p, err := readFirstLine(passwordFile)
			if err != nil {
				return "", err
			}
			password = p
		} else if passwordEnv != "" {
			if v := os.Getenv(passwordEnv); v != "" {
				password = v
			} else {
				fmt.Fprintf(os.Stderr, "Warning: Provided passwordenv %s is not set\n", passwordEnv)
			}
		}
	}
	if password == "" {
		if a.noInteraction {
			return "", errors.New("Master password is required. Try again in interactive mode or provide a password file or environment variable.")
		}
		password = promptSecret(promptMsg)
	}
	return password, nil
}

// dataDir returns the data directory, honoring BITWARDENCLI_APPDATA_DIR.
func dataDir() (string, error) {
	if d := os.Getenv("BITWARDENCLI_APPDATA_DIR"); d != "" {
		return filepath.Abs(d)
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cfg, "Bitwarden CLI-go"), nil
}

// client lazily opens the library client on data.json.
func (a *App) client() (*bw.Client, error) {
	if a.bw != nil {
		return a.bw, nil
	}
	dir, err := dataDir()
	if err != nil {
		return nil, err
	}
	opts := bw.Options{
		Store:             bw.FileStore(filepath.Join(dir, "data.json")),
		AllowInsecureHTTP: os.Getenv("BWCLI_ENV") == "development",
	}
	if os.Getenv("BWGO_DEBUG") == "1" {
		opts.DebugLog = os.Stderr
	}
	c, err := bw.New(opts)
	if err != nil {
		return nil, err
	}
	a.bw = c
	return c, nil
}

// requireAuthed mirrors exitIfNotAuthed.
func (a *App) requireAuthed() (*bw.Client, error) {
	c, err := a.client()
	if err != nil {
		return nil, err
	}
	if !c.LoggedIn() {
		return nil, bw.ErrNotLoggedIn
	}
	return c, nil
}

// isUnlocked reports whether the session key unlocks the vault.
func (a *App) isUnlocked() bool {
	c, err := a.requireAuthed()
	return err == nil && (c.Unlocked() || c.UnlockWithSession(a.session) == nil)
}

// requireUnlocked mirrors exitIfLocked: with interaction allowed, a locked
// vault prompts for the master password and is unlocked for this command only.
func (a *App) requireUnlocked() (*bw.Client, error) {
	c, err := a.requireAuthed()
	if err != nil {
		return nil, err
	}
	if a.isUnlocked() {
		return c, nil
	}
	if a.noInteraction {
		return nil, bw.ErrLocked
	}
	password, err := a.getPassword("", "", "", "Master password:")
	if err != nil {
		return nil, err
	}
	if err := c.Unlock(password); err != nil {
		return nil, err
	}
	return c, nil
}

// errResp converts a library error into a failed response.
func errResp(err error) output.Response {
	if r, ok := err.(*output.Response); ok {
		return *r
	}
	r := output.Error("%v", err)
	var mr *bw.MultipleResultsError
	if errors.As(err, &mr) {
		r.Data = mr.IDs
	}
	return r
}

// jsError formats errors thrown as JS Error objects ("Error: msg").
func jsError(msg string) output.Response { return output.Error("Error: %s", msg) }
