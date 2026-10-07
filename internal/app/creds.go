package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/jthy10/LocalLanView/internal/auth"
	"github.com/jthy10/LocalLanView/internal/store"
)

// EnvPassword is the environment variable checked for a console password.
const EnvPassword = "LOCALLANVIEW_PASSWORD"

// passwordInput finds a user-supplied password: -password-file, then the
// environment, then (only with -set-password) an interactive prompt.
// Returns "" if none was given.
func passwordInput(file string, prompt bool, stdin *os.File, out io.Writer) (string, string, error) {
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", "", fmt.Errorf("reading -password-file: %w", err)
		}
		pw := strings.TrimRight(string(b), "\r\n")
		if pw == "" {
			return "", "", errors.New("-password-file is empty")
		}
		return pw, "password file", nil
	}
	if pw := os.Getenv(EnvPassword); pw != "" {
		return pw, EnvPassword, nil
	}
	if !prompt {
		return "", "", nil
	}
	fd := int(stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", "", errors.New("-set-password needs a terminal for the prompt; use -password-file or " + EnvPassword + " instead")
	}
	fmt.Fprint(out, "New console password: ")
	a, err := term.ReadPassword(fd)
	fmt.Fprintln(out)
	if err != nil {
		return "", "", err
	}
	fmt.Fprint(out, "Repeat password: ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(out)
	if err != nil {
		return "", "", err
	}
	if string(a) != string(b) {
		return "", "", errors.New("passwords don't match")
	}
	return string(a), "prompt", nil
}

// credResult says what happened to the login so main can tell the user.
type credResult struct {
	Creds     *store.Credentials
	Generated string // set on first run: the password to print once
	Changed   bool   // a user-supplied password was applied
	Source    string
}

// ensureCredentials applies the password rules:
//   - a password given via file/env/prompt replaces the stored one;
//   - on first run without one, a random password is generated and only
//     its hash is stored;
//   - -user renames the account without touching the password.
func ensureCredentials(ctx context.Context, st *store.Store, user, pw, source string) (*credResult, error) {
	existing, err := st.Credentials(ctx)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	res := &credResult{Source: source}

	if pw != "" {
		if err := auth.CheckStrength(pw, user); err != nil {
			return nil, fmt.Errorf("password from %s rejected: %w", source, err)
		}
		if existing != nil && existing.User == user && !existing.Generated {
			if ok, _ := auth.VerifyPassword(pw, existing.Hash); ok {
				res.Creds = existing
				return res, nil
			}
		}
		hash, err := auth.HashPassword(pw)
		if err != nil {
			return nil, err
		}
		c := store.Credentials{User: user, Hash: hash, Generated: false}
		if err := st.SetCredentials(ctx, c); err != nil {
			return nil, err
		}
		res.Creds, res.Changed = &c, true
		return res, nil
	}

	if existing == nil {
		gen, err := auth.GeneratePassword()
		if err != nil {
			return nil, err
		}
		hash, err := auth.HashPassword(gen)
		if err != nil {
			return nil, err
		}
		c := store.Credentials{User: user, Hash: hash, Generated: true}
		if err := st.SetCredentials(ctx, c); err != nil {
			return nil, err
		}
		res.Creds, res.Generated = &c, gen
		return res, nil
	}

	if existing.User != user {
		existing.User = user
		if err := st.SetCredentials(ctx, *existing); err != nil {
			return nil, err
		}
	}
	res.Creds = existing
	return res, nil
}
