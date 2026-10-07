package alert

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHub(t *testing.T) {
	h := NewHub()
	ch, cancel := h.Subscribe()
	h.Publish(Message{Type: "event", Data: "x"})
	select {
	case b := <-ch:
		var m Message
		json.Unmarshal(b, &m)
		if m.Type != "event" {
			t.Fatalf("got %s", b)
		}
	case <-time.After(time.Second):
		t.Fatal("no message")
	}
	cancel()
	cancel() // idempotent
	h.Publish(Message{Type: "event"})
}

func TestWebhookValidation(t *testing.T) {
	ok := []string{"http://127.0.0.1:8123/api/webhook/x", "http://192.168.1.5/hook", "https://[fd00::5]/x", "http://localhost:9000", "http://10.0.0.2"}
	bad := []string{"http://example.com/hook", "http://8.8.8.8/x", "ftp://192.168.1.5/", "http://user:pw@192.168.1.5/", "not a url", "http://100.64.0.1/"}
	for _, u := range ok {
		if _, err := NewWebhook(u); err != nil {
			t.Errorf("%s rejected: %v", u, err)
		}
	}
	for _, u := range bad {
		if _, err := NewWebhook(u); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
}

func TestWebhookSend(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
	}))
	defer srv.Close()
	w, err := NewWebhook(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Send(context.Background(), map[string]string{"kind": "new_device"}); err != nil {
		t.Fatal(err)
	}
	if got["kind"] != "new_device" {
		t.Fatalf("got %v", got)
	}
}
