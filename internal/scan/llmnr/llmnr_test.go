package llmnr

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestRoundTrip(t *testing.T) {
	q := Query(netip.MustParseAddr("192.168.1.20"))
	var m dnsmessage.Message
	if err := m.Unpack(q); err != nil {
		t.Fatal(err)
	}
	if m.Questions[0].Name.String() != "20.1.168.192.in-addr.arpa." {
		t.Fatalf("question %s", m.Questions[0].Name)
	}
	m.Header.Response = true
	m.Answers = []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("GAMING-PC.")},
	}}
	b, _ := m.Pack()
	if got := ParseReply(b); got != "GAMING-PC" {
		t.Fatalf("ParseReply = %q", got)
	}
	if ParseReply(q) != "" {
		t.Fatal("a query must not parse as a reply")
	}
}
