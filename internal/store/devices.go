package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Device is one row of the inventory plus decoded JSON columns.
type Device struct {
	ID             int64             `json:"id"`
	Key            string            `json:"key"`
	MAC            string            `json:"mac,omitempty"`
	IP             string            `json:"ip,omitempty"`
	Hostname       string            `json:"hostname,omitempty"`
	HostnameSource string            `json:"hostnameSource,omitempty"`
	Vendor         string            `json:"vendor,omitempty"`
	VendorRegistry string            `json:"vendorRegistry,omitempty"`
	PrivateMAC     bool              `json:"privateMac"`
	Model          string            `json:"model,omitempty"`
	Type           string            `json:"type"`
	TypeConfidence string            `json:"typeConfidence"`
	TypeReasons    []string          `json:"typeReasons"`
	TypeOverride   string            `json:"typeOverride,omitempty"`
	CustomName     string            `json:"customName,omitempty"`
	Notes          string            `json:"notes,omitempty"`
	Tags           []string          `json:"tags"`
	Trusted        bool              `json:"trusted"`
	Attrs          map[string]string `json:"attrs"`
	Sources        []string          `json:"sources"`
	FirstSeen      time.Time         `json:"firstSeen"`
	LastSeen       time.Time         `json:"lastSeen"`
	OpenPorts      []int             `json:"openPorts"`
	ServiceCount   int               `json:"serviceCount"`
}

const deviceCols = `id, key, COALESCE(mac,''), COALESCE(ip,''), hostname, hostname_source, vendor, vendor_registry,
	private_mac, model, type, type_confidence, type_reasons, type_override, custom_name, notes, tags,
	trusted, attrs, sources, first_seen, last_seen`

type scanner interface{ Scan(...any) error }

func scanDevice(r scanner) (*Device, error) {
	var d Device
	var reasons, tags, attrs, sources string
	var first, last int64
	err := r.Scan(&d.ID, &d.Key, &d.MAC, &d.IP, &d.Hostname, &d.HostnameSource, &d.Vendor, &d.VendorRegistry,
		&d.PrivateMAC, &d.Model, &d.Type, &d.TypeConfidence, &reasons, &d.TypeOverride, &d.CustomName, &d.Notes,
		&tags, &d.Trusted, &attrs, &sources, &first, &last)
	if err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(reasons), &d.TypeReasons)
	json.Unmarshal([]byte(tags), &d.Tags)
	json.Unmarshal([]byte(attrs), &d.Attrs)
	json.Unmarshal([]byte(sources), &d.Sources)
	if d.Tags == nil {
		d.Tags = []string{}
	}
	if d.TypeReasons == nil {
		d.TypeReasons = []string{}
	}
	if d.Attrs == nil {
		d.Attrs = map[string]string{}
	}
	d.FirstSeen, d.LastSeen = fromMS(first), fromMS(last)
	return &d, nil
}

// DeviceByKey looks a device up by its identity key.
func (s *Store) DeviceByKey(ctx context.Context, key string) (*Device, error) {
	d, err := scanDevice(s.db.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE key = ?`, key))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}

// Device returns one device by id.
func (s *Store) Device(ctx context.Context, id int64) (*Device, error) {
	d, err := scanDevice(s.db.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return d, s.fillSummary(ctx, []*Device{d})
}

// DevicesByIP returns devices whose current IP is ip, most recently seen first.
func (s *Store) DevicesByIP(ctx context.Context, ip string) ([]*Device, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE ip = ? ORDER BY last_seen DESC`, ip)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Devices lists the whole inventory.
func (s *Store) Devices(ctx context.Context) ([]*Device, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+deviceCols+` FROM devices ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	var out []*Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, s.fillSummary(ctx, out)
}

func (s *Store) fillSummary(ctx context.Context, ds []*Device) error {
	byID := map[int64]*Device{}
	for _, d := range ds {
		byID[d.ID] = d
		d.OpenPorts = []int{}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT device_id, port FROM ports WHERE open = 1 ORDER BY port`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		var p int
		if err := rows.Scan(&id, &p); err != nil {
			rows.Close()
			return err
		}
		if d := byID[id]; d != nil {
			d.OpenPorts = append(d.OpenPorts, p)
		}
	}
	rows.Close()
	rows, err = s.db.QueryContext(ctx, `SELECT device_id, COUNT(*) FROM services GROUP BY device_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return err
		}
		if d := byID[id]; d != nil {
			d.ServiceCount = n
		}
	}
	return rows.Err()
}

// InsertDevice creates a device and returns its id.
func (s *Store) InsertDevice(ctx context.Context, d *Device) (int64, error) {
	var mac any
	if d.MAC != "" {
		mac = d.MAC
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO devices
		(key, mac, ip, vendor, vendor_registry, private_mac, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		d.Key, mac, d.IP, d.Vendor, d.VendorRegistry, d.PrivateMAC, ms(d.FirstSeen), ms(d.LastSeen))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// SaveDiscovered writes the fields the scanner owns (never the user's).
func (s *Store) SaveDiscovered(ctx context.Context, d *Device) error {
	var mac any
	if d.MAC != "" {
		mac = d.MAC
	}
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET key = ?, mac = ?, ip = ?, hostname = ?, hostname_source = ?,
		vendor = ?, vendor_registry = ?, private_mac = ?, model = ?, type = ?, type_confidence = ?, type_reasons = ?,
		attrs = ?, sources = ?, last_seen = ? WHERE id = ?`,
		d.Key, mac, d.IP, d.Hostname, d.HostnameSource, d.Vendor, d.VendorRegistry, d.PrivateMAC, d.Model,
		d.Type, d.TypeConfidence, toJSON(d.TypeReasons), toJSON(d.Attrs), toJSON(d.Sources), ms(d.LastSeen), d.ID)
	return err
}

// UserFields are the parts of a device a person edits.
type UserFields struct {
	CustomName   *string   `json:"customName"`
	Notes        *string   `json:"notes"`
	Tags         *[]string `json:"tags"`
	Trusted      *bool     `json:"trusted"`
	TypeOverride *string   `json:"typeOverride"`
}

// UpdateUser applies the non-nil fields.
func (s *Store) UpdateUser(ctx context.Context, id int64, u UserFields) error {
	var sets []string
	var args []any
	if u.CustomName != nil {
		sets, args = append(sets, "custom_name = ?"), append(args, strings.TrimSpace(*u.CustomName))
	}
	if u.Notes != nil {
		sets, args = append(sets, "notes = ?"), append(args, *u.Notes)
	}
	if u.Tags != nil {
		clean := []string{}
		seen := map[string]bool{}
		for _, t := range *u.Tags {
			t = strings.TrimSpace(t)
			if t != "" && !seen[strings.ToLower(t)] {
				seen[strings.ToLower(t)] = true
				clean = append(clean, t)
			}
		}
		sets, args = append(sets, "tags = ?"), append(args, toJSON(clean))
	}
	if u.Trusted != nil {
		sets, args = append(sets, "trusted = ?"), append(args, *u.Trusted)
	}
	if u.TypeOverride != nil {
		sets, args = append(sets, "type_override = ?"), append(args, strings.TrimSpace(*u.TypeOverride))
	}
	if len(sets) == 0 {
		return nil
	}
	args = append(args, id)
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET `+strings.Join(sets, ", ")+` WHERE id = ?`, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteDevice forgets a device and its history.
func (s *Store) DeleteDevice(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM devices WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// MergeInto moves history from one device to another, then deletes from.
func (s *Store) MergeInto(ctx context.Context, from, into int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range []string{"ip_history", "hostname_history", "services", "ports"} {
		if _, err := tx.ExecContext(ctx, `UPDATE OR IGNORE `+table+` SET device_id = ? WHERE device_id = ?`, into, from); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE events SET device_id = ? WHERE device_id = ?`, into, from); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE devices SET
		custom_name = CASE WHEN custom_name = '' THEN (SELECT custom_name FROM devices WHERE id = ?) ELSE custom_name END,
		first_seen = MIN(first_seen, (SELECT first_seen FROM devices WHERE id = ?))
		WHERE id = ?`, from, from, into); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM devices WHERE id = ?`, from); err != nil {
		return err
	}
	return tx.Commit()
}
