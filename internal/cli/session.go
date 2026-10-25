package cli

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/yangxiang/bw/internal/api"
	"github.com/yangxiang/bw/internal/crypto"
	"github.com/yangxiang/bw/internal/output"
	"github.com/yangxiang/bw/internal/state"
	"github.com/yangxiang/bw/internal/vault"
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
func (a *App) getPassword(password, passwordFile, passwordEnv, promptMsg string) (string, *output.Response) {
	if password == "" {
		if passwordFile != "" {
			p, err := readFirstLine(passwordFile)
			if err != nil {
				r := output.Error("%v", err)
				return "", &r
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
			r := output.Error("Master password is required. Try again in interactive mode or provide a password file or environment variable.")
			return "", &r
		}
		password = promptSecret(promptMsg)
	}
	return password, nil
}

// client returns an API client bound to the persisted state.
func (a *App) client() (*api.Client, error) {
	st, err := a.state()
	if err != nil {
		return nil, err
	}
	c := &api.Client{Env: st.Environment, DeviceID: st.DeviceID, Persist: st.Save}
	if st.Account != nil {
		c.Tokens = &st.Account.Tokens
	}
	return c, nil
}

func kdfParams(k state.KDF) crypto.KDFParams {
	p := crypto.KDFParams{Type: k.Type, Iterations: k.Iterations}
	if k.Memory != nil {
		p.Memory = *k.Memory
	}
	if k.Parallelism != nil {
		p.Parallelism = *k.Parallelism
	}
	return p
}

// newSession protects the user key under a fresh session key and returns
// the base64 session key (the BW_SESSION value).
func newSession(acc *state.Account, userKey *crypto.SymmetricKey) (string, error) {
	sk := crypto.GenerateSymmetricKey()
	enc, err := crypto.Encrypt(sk, userKey.Bytes())
	if err != nil {
		return "", err
	}
	acc.SessionUserKey = enc.String()
	return base64.StdEncoding.EncodeToString(sk.Bytes()), nil
}

// sessionUserKey decrypts the user key with the current session key.
func (a *App) sessionUserKey() (*crypto.SymmetricKey, error) {
	st, err := a.state()
	if err != nil {
		return nil, err
	}
	if st.Account == nil || st.Account.SessionUserKey == "" || a.session == "" {
		return nil, errors.New("locked")
	}
	raw, err := base64.StdEncoding.DecodeString(a.session)
	if err != nil {
		return nil, err
	}
	sk, err := crypto.NewSymmetricKey(raw)
	if err != nil {
		return nil, err
	}
	return crypto.DecryptKey(sk, st.Account.SessionUserKey)
}

// isUnlocked reports whether the current session key unlocks the vault.
func (a *App) isUnlocked() bool {
	_, err := a.sessionUserKey()
	return err == nil
}

// unlockWithPassword derives the user key from the master password.
func unlockWithPassword(acc *state.Account, password string) (*crypto.SymmetricKey, error) {
	mk, err := crypto.MasterKey(password, acc.Email, kdfParams(acc.KDF))
	if err != nil {
		return nil, err
	}
	uk, err := crypto.DecryptUserKey(mk, acc.EncUserKey)
	if err != nil {
		return nil, errors.New("Invalid master password.")
	}
	return uk, nil
}

// requireAuthed mirrors exitIfNotAuthed.
func (a *App) requireAuthed() (*state.State, *output.Response) {
	st, err := a.state()
	if err != nil {
		r := output.Error("%v", err)
		return nil, &r
	}
	if st.Account == nil || st.Account.Tokens.AccessToken == "" {
		r := output.Error("You are not logged in.")
		return nil, &r
	}
	return st, nil
}

// requireUnlocked mirrors exitIfLocked: with interaction allowed, a locked
// vault prompts for the master password and is unlocked for this command only.
func (a *App) requireUnlocked() (*crypto.SymmetricKey, *output.Response) {
	st, resp := a.requireAuthed()
	if resp != nil {
		return nil, resp
	}
	if uk, err := a.sessionUserKey(); err == nil {
		return uk, nil
	}
	if a.noInteraction {
		r := output.Error("Vault is locked.")
		return nil, &r
	}
	password, resp := a.getPassword("", "", "", "Master password:")
	if resp != nil {
		return nil, resp
	}
	uk, err := unlockWithPassword(st.Account, password)
	if err != nil {
		r := output.Error("%v", err)
		return nil, &r
	}
	return uk, nil
}

// openVault ensures the vault is unlocked and returns decrypted access to it.
func (a *App) openVault() (*vault.Vault, *output.Response) {
	uk, resp := a.requireUnlocked()
	if resp != nil {
		return nil, resp
	}
	st, _ := a.state()
	v, err := vault.Open(st.Account.Vault, uk, st.Account.EncPrivateKey)
	if err != nil {
		r := output.Error("%v", err)
		return nil, &r
	}
	return v, nil
}
