package store

import (
	"context"
	"time"
)

// Retention limits for Prune. Devices someone has named, tagged, noted,
// trusted or retyped are never forgotten automatically.
const (
	keepEvents          = 90 * 24 * time.Hour
	maxEvents           = 10000
	keepHistory         = 180 * 24 * time.Hour // old IPs, hostnames, services, closed ports
	keepDevice          = 365 * 24 * time.Hour
	keepTransientDevice = 30 * 24 * time.Hour // randomized MACs and IP-only rows
)

// PruneStats counts what Prune removed.
type PruneStats struct {
	Devices, Events, History int64
}

// Prune drops data older than the retention limits so the database doesn't
// grow forever: phones with rotating MACs alone add a device every few
// weeks. A device's current IP and names are kept however old they are.
func (s *Store) Prune(ctx context.Context, now time.Time) (PruneStats, error) {
	var st PruneStats
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return st, err
	}
	defer tx.Rollback()
	exec := func(n *int64, q string, args ...any) error {
		if err != nil {
			return err
		}
		res, e := tx.ExecContext(ctx, q, args...)
		if e != nil {
			err = e
			return err
		}
		c, _ := res.RowsAffected()
		*n += c
		return nil
	}
	cutoff := func(d time.Duration) int64 { return ms(now.Add(-d)) }

	exec(&st.Devices, `DELETE FROM devices
		WHERE custom_name = '' AND notes = '' AND tags = '[]' AND trusted = 0 AND type_override = ''
		AND (last_seen < ? OR ((private_mac = 1 OR key LIKE 'ip:%') AND last_seen < ?))`,
		cutoff(keepDevice), cutoff(keepTransientDevice))
	exec(&st.Events, `DELETE FROM events WHERE time < ?`, cutoff(keepEvents))
	exec(&st.Events, `DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY time DESC, id DESC LIMIT ?)`, maxEvents)
	h := cutoff(keepHistory)
	exec(&st.History, `DELETE FROM ip_history WHERE last_seen < ?
		AND ip != COALESCE((SELECT ip FROM devices WHERE id = device_id), '')`, h)
	exec(&st.History, `DELETE FROM hostname_history WHERE last_seen < ?
		AND hostname != (SELECT hostname FROM devices WHERE id = device_id)`, h)
	exec(&st.History, `DELETE FROM services WHERE last_seen < ?`, h)
	exec(&st.History, `DELETE FROM ports WHERE open = 0 AND last_seen < ?`, h)
	// Rows of forgotten devices, in case foreign keys were ever off.
	var orphans int64
	for _, t := range []string{"ip_history", "hostname_history", "services", "ports"} {
		exec(&orphans, `DELETE FROM `+t+` WHERE device_id NOT IN (SELECT id FROM devices)`)
	}
	exec(&orphans, `DELETE FROM settings WHERE key LIKE 'portscan:%'
		AND CAST(substr(key, 10) AS INTEGER) NOT IN (SELECT id FROM devices)`)
	if err != nil {
		return st, err
	}
	return st, tx.Commit()
}
