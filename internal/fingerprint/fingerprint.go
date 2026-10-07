// Package fingerprint guesses what kind of device something is by weighing
// independent signals (vendor, advertised services, names, open ports)
// against a set of embedded rules.
package fingerprint

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

//go:embed rules.json
var rulesJSON []byte

// Signals is everything known about one device.
type Signals struct {
	Vendor    string
	Private   bool // randomized MAC
	Hostnames []string
	MDNS      []string // service types, e.g. "_googlecast._tcp"
	MDNSText  []string // TXT values worth matching (model strings etc.)
	SSDP      []string // device types, models, manufacturers, server headers
	Ports     []int
	Banners   []string
}

// Guess is the result of classification.
type Guess struct {
	Type       string   `json:"type"`
	Confidence string   `json:"confidence"` // high, medium, low, none
	Score      int      `json:"score"`
	Reasons    []string `json:"reasons,omitempty"`
}

// Rule is one weighted hint. Every field that is set must match.
type Rule struct {
	Type     string   `json:"type"`
	Weight   int      `json:"weight"`
	Why      string   `json:"why"`
	Vendor   string   `json:"vendor,omitempty"`   // regex, case-insensitive
	Hostname string   `json:"hostname,omitempty"` // regex
	MDNS     []string `json:"mdns,omitempty"`     // any of these service types
	Text     string   `json:"text,omitempty"`     // regex over mDNS TXT / SSDP strings
	SSDP     string   `json:"ssdp,omitempty"`     // regex over SSDP strings
	AllPorts []int    `json:"allPorts,omitempty"` // every port open
	AnyPorts []int    `json:"anyPorts,omitempty"` // at least one open
	Banner   string   `json:"banner,omitempty"`   // regex over banners
	Private  *bool    `json:"private,omitempty"`

	vendor, hostname, text, ssdp, banner *regexp.Regexp
}

// Engine holds compiled rules.
type Engine struct {
	Rules []*Rule
}

// Default loads the embedded rule set.
func Default() *Engine {
	e, err := Load(rulesJSON)
	if err != nil {
		panic("fingerprint: embedded rules: " + err.Error())
	}
	return e
}

// Load compiles rules from JSON. This is also the hook for user-supplied
// rule files later on.
func Load(b []byte) (*Engine, error) {
	var rules []*Rule
	if err := json.Unmarshal(b, &rules); err != nil {
		return nil, err
	}
	for i, r := range rules {
		if r.Type == "" || r.Weight == 0 {
			return nil, fmt.Errorf("rule %d: type and weight are required", i)
		}
		var err error
		compile := func(s string) *regexp.Regexp {
			if s == "" || err != nil {
				return nil
			}
			var re *regexp.Regexp
			re, err = regexp.Compile("(?i)" + s)
			return re
		}
		r.vendor = compile(r.Vendor)
		r.hostname = compile(r.Hostname)
		r.text = compile(r.Text)
		r.ssdp = compile(r.SSDP)
		r.banner = compile(r.Banner)
		if err != nil {
			return nil, fmt.Errorf("rule %d (%s): %v", i, r.Why, err)
		}
		if r.vendor == nil && r.hostname == nil && r.text == nil && r.ssdp == nil && r.banner == nil &&
			len(r.MDNS) == 0 && len(r.AllPorts) == 0 && len(r.AnyPorts) == 0 && r.Private == nil {
			return nil, fmt.Errorf("rule %d (%s) has no conditions", i, r.Why)
		}
	}
	return &Engine{Rules: rules}, nil
}

func anyMatch(re *regexp.Regexp, ss []string) bool {
	for _, s := range ss {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func (r *Rule) match(s *Signals, ports map[int]bool, mdns map[string]bool) bool {
	if r.vendor != nil && (s.Vendor == "" || !r.vendor.MatchString(s.Vendor)) {
		return false
	}
	if r.hostname != nil && !anyMatch(r.hostname, s.Hostnames) {
		return false
	}
	if r.text != nil && !anyMatch(r.text, s.MDNSText) && !anyMatch(r.text, s.SSDP) {
		return false
	}
	if r.ssdp != nil && !anyMatch(r.ssdp, s.SSDP) {
		return false
	}
	if r.banner != nil && !anyMatch(r.banner, s.Banners) {
		return false
	}
	if r.Private != nil && *r.Private != s.Private {
		return false
	}
	if len(r.MDNS) > 0 {
		ok := false
		for _, t := range r.MDNS {
			if mdns[strings.ToLower(t)] {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	for _, p := range r.AllPorts {
		if !ports[p] {
			return false
		}
	}
	if len(r.AnyPorts) > 0 {
		ok := false
		for _, p := range r.AnyPorts {
			if ports[p] {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// Classify scores every type and returns the best guess.
func (e *Engine) Classify(s Signals) Guess {
	ports := map[int]bool{}
	for _, p := range s.Ports {
		ports[p] = true
	}
	mdns := map[string]bool{}
	for _, t := range s.MDNS {
		mdns[strings.ToLower(t)] = true
	}
	scores := map[string]int{}
	reasons := map[string][]string{}
	for _, r := range e.Rules {
		if r.match(&s, ports, mdns) {
			scores[r.Type] += r.Weight
			reasons[r.Type] = append(reasons[r.Type], r.Why)
		}
	}
	type kv struct {
		t string
		s int
	}
	var ranked []kv
	for t, sc := range scores {
		if sc > 0 {
			ranked = append(ranked, kv{t, sc})
		}
	}
	if len(ranked) == 0 {
		return Guess{Type: "Unknown", Confidence: "none"}
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].s != ranked[j].s {
			return ranked[i].s > ranked[j].s
		}
		return ranked[i].t < ranked[j].t
	})
	best := ranked[0]
	level := 0 // 0 low, 1 medium, 2 high
	switch {
	case best.s >= 8:
		level = 2
	case best.s >= 4:
		level = 1
	}
	// Close competition means we're less sure.
	if len(ranked) > 1 && best.s-ranked[1].s < 3 && level > 0 {
		level--
	}
	return Guess{
		Type:       best.t,
		Confidence: []string{"low", "medium", "high"}[level],
		Score:      best.s,
		Reasons:    reasons[best.t],
	}
}
