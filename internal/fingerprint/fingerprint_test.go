package fingerprint

import "testing"

func TestEmbeddedRulesLoad(t *testing.T) {
	e := Default()
	if len(e.Rules) < 50 {
		t.Fatalf("only %d rules", len(e.Rules))
	}
}

func TestClassify(t *testing.T) {
	e := Default()
	tests := []struct {
		name string
		s    Signals
		want string
		conf string
	}{
		{"chromecast", Signals{Vendor: "Google, Inc.", MDNS: []string{"_googlecast._tcp"}, MDNSText: []string{"Chromecast Ultra"}, Ports: []int{8008, 8009}}, "Streaming Device", "high"},
		{"printer", Signals{Vendor: "Brother Industries, LTD.", MDNS: []string{"_ipp._tcp", "_uscan._tcp"}, Ports: []int{80, 631, 9100}}, "Printer", "high"},
		{"router", Signals{Vendor: "NETGEAR", SSDP: []string{"urn:schemas-upnp-org:device:InternetGatewayDevice:1"}, Ports: []int{53, 80, 443}}, "Router", "high"},
		{"windows", Signals{Vendor: "Micro-Star INTL CO., LTD.", Hostnames: []string{"DESKTOP-7Q1ABCD"}, Ports: []int{135, 139, 445}}, "Windows PC", "high"},
		{"iphone", Signals{Private: true, Hostnames: []string{"Jakes-iPhone"}, Ports: []int{62078}}, "Phone", "high"},
		{"sonos", Signals{Vendor: "Sonos, Inc.", Ports: []int{1400}}, "Smart Speaker", "high"},
		{"pi", Signals{Vendor: "Raspberry Pi Trading Ltd", Hostnames: []string{"raspberrypi"}, Ports: []int{22}}, "Raspberry Pi / SBC", "high"},
		{"esp", Signals{Vendor: "Espressif Inc.", MDNS: []string{"_esphomelib._tcp"}}, "IoT Device", "high"},
		{"nas", Signals{Vendor: "Synology Incorporated", Ports: []int{445, 5000, 5001}}, "NAS", "high"},
		{"camera", Signals{Vendor: "Hangzhou Hikvision Digital Technology Co.,Ltd.", Ports: []int{80, 554}}, "Camera", "high"},
		{"ssh only", Signals{Ports: []int{22}}, "Server", "low"},
		{"nothing", Signals{}, "Unknown", "none"},
	}
	for _, tt := range tests {
		g := e.Classify(tt.s)
		if g.Type != tt.want || g.Confidence != tt.conf {
			t.Errorf("%s: got %s/%s (score %d, %v), want %s/%s", tt.name, g.Type, g.Confidence, g.Score, g.Reasons, tt.want, tt.conf)
		}
	}
}

func TestReasonsExplainResult(t *testing.T) {
	g := Default().Classify(Signals{MDNS: []string{"_ipp._tcp"}})
	if g.Type != "Printer" || len(g.Reasons) != 1 || g.Reasons[0] != "advertises printing over mDNS" {
		t.Fatalf("got %+v", g)
	}
}

func TestCloseCallLowersConfidence(t *testing.T) {
	e, err := Load([]byte(`[
		{"type":"A","weight":5,"why":"a","anyPorts":[1]},
		{"type":"B","weight":4,"why":"b","anyPorts":[1]}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	g := e.Classify(Signals{Ports: []int{1}})
	if g.Type != "A" || g.Confidence != "low" {
		t.Fatalf("got %+v", g)
	}
}

func TestLoadRejectsBadRules(t *testing.T) {
	for _, js := range []string{
		`[{"type":"A","weight":1,"why":"x"}]`,
		`[{"type":"A","weight":1,"why":"x","vendor":"("}]`,
		`[{"weight":1,"why":"x","vendor":"a"}]`,
	} {
		if _, err := Load([]byte(js)); err == nil {
			t.Errorf("Load(%s) should fail", js)
		}
	}
}
