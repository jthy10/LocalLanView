package store

// Migrations run in order; the index+1 is stored in PRAGMA user_version.
// Never edit an existing entry, only append.
var migrations = []string{
	`
CREATE TABLE devices (
	id              INTEGER PRIMARY KEY,
	key             TEXT NOT NULL UNIQUE, -- "mac:aa:bb:..." or "ip:192.168.1.5" when no MAC is known
	mac             TEXT,
	ip              TEXT,
	hostname        TEXT NOT NULL DEFAULT '',
	hostname_source TEXT NOT NULL DEFAULT '',
	vendor          TEXT NOT NULL DEFAULT '',
	vendor_registry TEXT NOT NULL DEFAULT '',
	private_mac     INTEGER NOT NULL DEFAULT 0,
	model           TEXT NOT NULL DEFAULT '',
	type            TEXT NOT NULL DEFAULT 'Unknown',
	type_confidence TEXT NOT NULL DEFAULT 'none',
	type_reasons    TEXT NOT NULL DEFAULT '[]',
	type_override   TEXT NOT NULL DEFAULT '',
	custom_name     TEXT NOT NULL DEFAULT '',
	notes           TEXT NOT NULL DEFAULT '',
	tags            TEXT NOT NULL DEFAULT '[]',
	trusted         INTEGER NOT NULL DEFAULT 0,
	attrs           TEXT NOT NULL DEFAULT '{}',
	sources         TEXT NOT NULL DEFAULT '[]',
	first_seen      INTEGER NOT NULL,
	last_seen       INTEGER NOT NULL
);
CREATE INDEX devices_ip ON devices(ip);

CREATE TABLE ip_history (
	device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
	ip         TEXT NOT NULL,
	first_seen INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL,
	PRIMARY KEY (device_id, ip)
);

CREATE TABLE hostname_history (
	device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
	hostname   TEXT NOT NULL,
	source     TEXT NOT NULL,
	first_seen INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL,
	PRIMARY KEY (device_id, hostname, source)
);

CREATE TABLE services (
	device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
	source     TEXT NOT NULL,
	type       TEXT NOT NULL,
	name       TEXT NOT NULL DEFAULT '',
	port       INTEGER NOT NULL DEFAULT 0,
	info       TEXT NOT NULL DEFAULT '{}',
	first_seen INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL,
	PRIMARY KEY (device_id, source, type, name)
);

CREATE TABLE ports (
	device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
	port       INTEGER NOT NULL,
	service    TEXT NOT NULL DEFAULT '',
	banner     TEXT NOT NULL DEFAULT '',
	open       INTEGER NOT NULL DEFAULT 1,
	first_seen INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL,
	PRIMARY KEY (device_id, port)
);

CREATE TABLE events (
	id           INTEGER PRIMARY KEY,
	time         INTEGER NOT NULL,
	kind         TEXT NOT NULL,
	device_id    INTEGER REFERENCES devices(id) ON DELETE SET NULL,
	message      TEXT NOT NULL,
	data         TEXT NOT NULL DEFAULT '{}',
	acknowledged INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX events_time ON events(time);

CREATE TABLE settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

CREATE TABLE auth (
	user      TEXT PRIMARY KEY,
	hash      TEXT NOT NULL,
	generated INTEGER NOT NULL, -- 1 = random first-run password, never set by a person
	updated   INTEGER NOT NULL
);
`,
}

func (s *Store) migrate() error {
	var v int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	for i := v; i < len(migrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return err
		}
		// PRAGMA doesn't take bound parameters.
		if _, err := tx.Exec(`PRAGMA user_version = ` + itoa(i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
