package store

import (
	"context"
	"encoding/json"
	"time"
)

// HistoryEntry is one IP or hostname a device has used.
type HistoryEntry struct {
	Value     string    `json:"value"`
	Source    string    `json:"source,omitempty"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
}

// Service is a stored advertised service.
type Service struct {
	Source    string            `json:"source"`
	Type      string            `json:"type"`
	Name      string            `json:"name,omitempty"`
	Port      int               `json:"port,omitempty"`
	Info      map[string]string `json:"info,omitempty"`
	FirstSeen time.Time         `json:"firstSeen"`
	LastSeen  time.Time         `json:"lastSeen"`
}

// Port is a stored TCP port result.
type Port struct {
	Port      int       `json:"port"`
	Service   string    `json:"service,omitempty"`
	Banner    string    `json:"banner,omitempty"`
	Open      bool      `json:"open"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
}

// TouchIP records that the device used ip at t. Returns true if new.
func (s *Store) TouchIP(ctx context.Context, id int64, ip string, t time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO ip_history(device_id, ip, first_seen, last_seen) VALUES(?, ?, ?, ?)
		ON CONFLICT(device_id, ip) DO NOTHING`, id, ip, ms(t), ms(t))
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return true, nil
	}
	_, err = s.db.ExecContext(ctx, `UPDATE ip_history SET last_seen = MAX(last_seen, ?) WHERE device_id = ? AND ip = ?`, ms(t), id, ip)
	return false, err
}

// TouchHostname records a hostname seen for the device.
func (s *Store) TouchHostname(ctx context.Context, id int64, name, source string, t time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO hostname_history(device_id, hostname, source, first_seen, last_seen)
		VALUES(?, ?, ?, ?, ?)
		ON CONFLICT(device_id, hostname, source) DO UPDATE SET last_seen = MAX(last_seen, excluded.last_seen)`,
		id, name, source, ms(t), ms(t))
	return err
}

// UpsertService records an advertised service. Returns true if new.
func (s *Store) UpsertService(ctx context.Context, id int64, svc Service, t time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO services(device_id, source, type, name, port, info, first_seen, last_seen)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(device_id, source, type, name) DO NOTHING`,
		id, svc.Source, svc.Type, svc.Name, svc.Port, toJSON(svc.Info), ms(t), ms(t))
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return true, nil
	}
	_, err = s.db.ExecContext(ctx, `UPDATE services SET port = ?, info = ?, last_seen = ?
		WHERE device_id = ? AND source = ? AND type = ? AND name = ?`,
		svc.Port, toJSON(svc.Info), ms(t), id, svc.Source, svc.Type, svc.Name)
	return false, err
}

// HasPortScan reports whether the device has ever been port scanned.
func (s *Store) HasPortScan(ctx context.Context, id int64) (bool, error) {
	v, err := s.Setting(ctx, "portscan:"+itoa(int(id)))
	return err == nil && v == "1", nil
}

// SetPorts replaces the open port set from a complete scan. Ports not in
// open are marked closed but kept for history. Returns newly opened ports.
func (s *Store) SetPorts(ctx context.Context, id int64, open []Port, t time.Time) ([]int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	prev := map[int]bool{}
	rows, err := tx.QueryContext(ctx, `SELECT port FROM ports WHERE device_id = ? AND open = 1`, id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p int
		rows.Scan(&p)
		prev[p] = true
	}
	rows.Close()
	if _, err := tx.ExecContext(ctx, `UPDATE ports SET open = 0 WHERE device_id = ?`, id); err != nil {
		return nil, err
	}
	var added []int
	for _, p := range open {
		if !prev[p.Port] {
			added = append(added, p.Port)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO ports(device_id, port, service, banner, open, first_seen, last_seen)
			VALUES(?, ?, ?, ?, 1, ?, ?)
			ON CONFLICT(device_id, port) DO UPDATE SET service = excluded.service,
				banner = CASE WHEN excluded.banner != '' THEN excluded.banner ELSE banner END,
				open = 1, last_seen = excluded.last_seen`,
			id, p.Port, p.Service, p.Banner, ms(t), ms(t)); err != nil {
			return nil, err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES(?, '1') ON CONFLICT(key) DO NOTHING`,
		"portscan:"+itoa(int(id))); err != nil {
		return nil, err
	}
	return added, tx.Commit()
}

// IPHistory lists every IP the device has used.
func (s *Store) IPHistory(ctx context.Context, id int64) ([]HistoryEntry, error) {
	return s.history(ctx, `SELECT ip, '', first_seen, last_seen FROM ip_history WHERE device_id = ? ORDER BY last_seen DESC`, id)
}

// HostnameHistory lists every hostname seen for the device.
func (s *Store) HostnameHistory(ctx context.Context, id int64) ([]HistoryEntry, error) {
	return s.history(ctx, `SELECT hostname, source, first_seen, last_seen FROM hostname_history WHERE device_id = ? ORDER BY last_seen DESC`, id)
}

func (s *Store) history(ctx context.Context, q string, id int64) ([]HistoryEntry, error) {
	rows, err := s.db.QueryContext(ctx, q, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HistoryEntry{}
	for rows.Next() {
		var h HistoryEntry
		var f, l int64
		if err := rows.Scan(&h.Value, &h.Source, &f, &l); err != nil {
			return nil, err
		}
		h.FirstSeen, h.LastSeen = fromMS(f), fromMS(l)
		out = append(out, h)
	}
	return out, rows.Err()
}

// Services lists a device's advertised services.
func (s *Store) Services(ctx context.Context, id int64) ([]Service, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT source, type, name, port, info, first_seen, last_seen
		FROM services WHERE device_id = ? ORDER BY source, type, name`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Service{}
	for rows.Next() {
		var sv Service
		var info string
		var f, l int64
		if err := rows.Scan(&sv.Source, &sv.Type, &sv.Name, &sv.Port, &info, &f, &l); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(info), &sv.Info)
		sv.FirstSeen, sv.LastSeen = fromMS(f), fromMS(l)
		out = append(out, sv)
	}
	return out, rows.Err()
}

// Ports lists a device's port history.
func (s *Store) Ports(ctx context.Context, id int64) ([]Port, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT port, service, banner, open, first_seen, last_seen
		FROM ports WHERE device_id = ? ORDER BY open DESC, port`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Port{}
	for rows.Next() {
		var p Port
		var f, l int64
		if err := rows.Scan(&p.Port, &p.Service, &p.Banner, &p.Open, &f, &l); err != nil {
			return nil, err
		}
		p.FirstSeen, p.LastSeen = fromMS(f), fromMS(l)
		out = append(out, p)
	}
	return out, rows.Err()
}
