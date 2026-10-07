package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Webhook POSTs alerts as JSON to a local-only URL.
type Webhook struct {
	URL    string
	client *http.Client
}

// NewWebhook validates that raw points at this machine or a private
// address. Hostnames other than localhost are refused so a typo or DNS
// answer can't send the network map to the Internet.
func NewWebhook(raw string) (*Webhook, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("webhook %q must be an http(s) URL", raw)
	}
	if u.User != nil {
		return nil, errors.New("webhook URL must not contain credentials")
	}
	if err := CheckLocalHost(u.Hostname()); err != nil {
		return nil, fmt.Errorf("webhook: %w", err)
	}
	return &Webhook{URL: u.String(), client: &http.Client{
		Timeout:       5 * time.Second,
		Transport:     &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// CheckLocalHost accepts localhost and loopback, private (RFC 1918 / ULA)
// and link-local IP literals.
func CheckLocalHost(host string) error {
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("host %q must be an IP address on your network (or localhost)", host)
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return nil
	}
	return fmt.Errorf("%s is not a local/private address", ip)
}

// Send delivers one payload.
func (w *Webhook) Send(ctx context.Context, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "LocalLanView")
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}
