// Package store keeps the device inventory in a local SQLite file.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	_ "modernc.org/sqlite" // pure Go, no cgo
)

// Store wraps the database. All access goes through one connection, which
// keeps SQLite locking trivial; the inventory is small.
type Store struct {
	db   *sql.DB
	path string
}

var ErrNotFound = errors.New("not found")

// Open creates (if needed) and opens the database at path with owner-only
// permissions.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	if err := Restrict(path); err != nil {
		return nil, err
	}

	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(NORMAL)")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, path: path}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating database: %w", err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		Restrict(path + suffix)
	}
	return s, nil
}

// Restrict sets owner-only permissions on a file (no-op on Windows, where
// the per-user data directory is already private).
func Restrict(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if err := os.Chmod(path, 0o600); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s *Store) Close() error { return s.db.Close() }

// Path returns the database file location.
func (s *Store) Path() string { return s.path }

// DB exposes the handle for tests and backups.
func (s *Store) DB() *sql.DB { return s.db }

func ms(t time.Time) int64 { return t.UnixMilli() }

func fromMS(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMilli(v)
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// Setting reads a value from the settings table.
func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}

// SetSetting writes a value to the settings table.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}
