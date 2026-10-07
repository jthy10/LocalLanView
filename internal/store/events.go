package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Event kinds.
const (
	EventNewDevice  = "new_device"
	EventNewPort    = "new_port"
	EventMACChanged = "ip_mac_changed"
	EventDeviceBack = "device_back"
)

// Event is something worth telling the user about.
type Event struct {
	ID           int64             `json:"id"`
	Time         time.Time         `json:"time"`
	Kind         string            `json:"kind"`
	DeviceID     int64             `json:"deviceId,omitempty"`
	Message      string            `json:"message"`
	Data         map[string]string `json:"data,omitempty"`
	Acknowledged bool              `json:"acknowledged"`
}

// AddEvent stores e and fills in its ID.
func (s *Store) AddEvent(ctx context.Context, e *Event) error {
	var dev any
	if e.DeviceID != 0 {
		dev = e.DeviceID
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO events(time, kind, device_id, message, data) VALUES(?, ?, ?, ?, ?)`,
		ms(e.Time), e.Kind, dev, e.Message, toJSON(e.Data))
	if err != nil {
		return err
	}
	e.ID, err = res.LastInsertId()
	return err
}

// Events returns the newest events first. deviceID 0 means all devices.
func (s *Store) Events(ctx context.Context, deviceID int64, limit int) ([]Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q := `SELECT id, time, kind, COALESCE(device_id, 0), message, data, acknowledged FROM events`
	args := []any{}
	if deviceID != 0 {
		q += ` WHERE device_id = ?`
		args = append(args, deviceID)
	}
	q += ` ORDER BY time DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		var t int64
		var data string
		if err := rows.Scan(&e.ID, &t, &e.Kind, &e.DeviceID, &e.Message, &data, &e.Acknowledged); err != nil {
			return nil, err
		}
		e.Time = fromMS(t)
		json.Unmarshal([]byte(data), &e.Data)
		out = append(out, e)
	}
	return out, rows.Err()
}

// UnacknowledgedCount is the number for the alert badge.
func (s *Store) UnacknowledgedCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE acknowledged = 0`).Scan(&n)
	return n, err
}

// AckEvents marks events as read; id 0 marks all.
func (s *Store) AckEvents(ctx context.Context, id int64) error {
	if id == 0 {
		_, err := s.db.ExecContext(ctx, `UPDATE events SET acknowledged = 1 WHERE acknowledged = 0`)
		return err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE events SET acknowledged = 1 WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Credentials is the stored login.
type Credentials struct {
	User      string
	Hash      string
	Generated bool
	Updated   time.Time
}

// Credentials returns the console login, or ErrNotFound on first run.
func (s *Store) Credentials(ctx context.Context) (*Credentials, error) {
	var c Credentials
	var t int64
	err := s.db.QueryRowContext(ctx, `SELECT user, hash, generated, updated FROM auth LIMIT 1`).Scan(&c.User, &c.Hash, &c.Generated, &t)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	c.Updated = fromMS(t)
	return &c, err
}

// SetCredentials replaces the console login (there is exactly one).
func (s *Store) SetCredentials(ctx context.Context, c Credentials) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM auth`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO auth(user, hash, generated, updated) VALUES(?, ?, ?, ?)`,
		c.User, c.Hash, c.Generated, ms(time.Now())); err != nil {
		return err
	}
	return tx.Commit()
}
