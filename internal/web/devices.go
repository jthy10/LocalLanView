package web

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jthy10/LocalLanView/internal/auth"
	"github.com/jthy10/LocalLanView/internal/store"
)

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	ds, err := s.Store.Devices(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	if ds == nil {
		ds = []*store.Device{}
	}
	writeJSON(w, http.StatusOK, ds)
}

func (s *Server) handleDevice(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad id")
		return
	}
	ctx := r.Context()
	d, err := s.Store.Device(ctx, id)
	if err != nil {
		storeError(w, err)
		return
	}
	svcs, err1 := s.Store.Services(ctx, id)
	ports, err2 := s.Store.Ports(ctx, id)
	ips, err3 := s.Store.IPHistory(ctx, id)
	names, err4 := s.Store.HostnameHistory(ctx, id)
	events, err5 := s.Store.Events(ctx, id, 100)
	for _, e := range []error{err1, err2, err3, err4, err5} {
		if e != nil {
			storeError(w, e)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"device": d, "services": svcs, "ports": ports,
		"ipHistory": ips, "hostnameHistory": names, "events": events,
	})
}

func (s *Server) handleUpdateDevice(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad id")
		return
	}
	var u store.UserFields
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&u); err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	if u.CustomName != nil && len(*u.CustomName) > 100 ||
		u.Notes != nil && len(*u.Notes) > 4000 ||
		u.TypeOverride != nil && len(*u.TypeOverride) > 60 ||
		u.Tags != nil && len(*u.Tags) > 20 {
		writeError(w, http.StatusBadRequest, "value too long")
		return
	}
	if u.Tags != nil {
		for _, t := range *u.Tags {
			if len(t) > 40 {
				writeError(w, http.StatusBadRequest, "tag too long")
				return
			}
		}
	}
	if err := s.Store.UpdateUser(r.Context(), id, u); err != nil {
		storeError(w, err)
		return
	}
	d, err := s.Store.Device(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleDeleteDevice(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad id")
		return
	}
	if err := s.Store.DeleteDevice(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	es, err := s.Store.Events(r.Context(), 0, limit)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, es)
}

func (s *Server) handleAck(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	if err := s.Store.AckEvents(r.Context(), req.ID); err != nil {
		storeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	ds, err := s.Store.Devices(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	stamp := time.Now().Format("20060102-150405")
	if r.URL.Query().Get("format") == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="locallanview-`+stamp+`.csv"`)
		cw := csv.NewWriter(w)
		cw.Write([]string{"id", "name", "hostname", "ip", "mac", "vendor", "private_mac", "type", "confidence",
			"model", "trusted", "tags", "open_ports", "first_seen", "last_seen"})
		for _, d := range ds {
			ports := make([]string, len(d.OpenPorts))
			for i, p := range d.OpenPorts {
				ports[i] = strconv.Itoa(p)
			}
			typ := d.Type
			if d.TypeOverride != "" {
				typ = d.TypeOverride
			}
			cw.Write(csvSafe([]string{strconv.FormatInt(d.ID, 10), d.CustomName, d.Hostname, d.IP, d.MAC, d.Vendor,
				strconv.FormatBool(d.PrivateMAC), typ, d.TypeConfidence, d.Model, strconv.FormatBool(d.Trusted),
				strings.Join(d.Tags, ";"), strings.Join(ports, ";"),
				d.FirstSeen.UTC().Format(time.RFC3339), d.LastSeen.UTC().Format(time.RFC3339)}))
		}
		cw.Flush()
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="locallanview-`+stamp+`.json"`)
	writeJSON(w, http.StatusOK, ds)
}

// csvSafe defuses spreadsheet formula injection from device-supplied names.
func csvSafe(row []string) []string {
	for i, v := range row {
		if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
			row[i] = "'" + v
		}
	}
	return row
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request, _ *auth.Session) {
	rc := http.NewResponseController(w)
	rc.SetWriteDeadline(time.Time{}) // the stream is long-lived
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	rc.Flush()

	ch, cancel := s.Hub.Subscribe()
	defer cancel()
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case b, ok := <-ch:
			if !ok {
				return
			}
			if _, err := w.Write(append(append([]byte("data: "), b...), '\n', '\n')); err != nil {
				return
			}
			rc.Flush()
		case <-ping.C:
			if _, err := w.Write([]byte(": ping\n\n")); err != nil {
				return
			}
			rc.Flush()
		}
	}
}
